import argparse
import base64
import json
import re
import sys
import urllib.request
from datetime import datetime

# gfwlist 官方源
GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# 默认直连规则 (Exclude)
DEFAULT_EXCLUDES = [
    {"type": "regex", "title": "10.*.*.*", "pattern": r"^(http|ws)s?://10(\.\d+){3}/", "active": True},
    {"type": "regex", "title": "127.*.*.*", "pattern": r"^(http|ws)s?://127(\.\d+){3}/", "active": True},
    {"type": "regex", "title": "172.16.*.*", "pattern": r"^(http|ws)s?://172\.16(\.\d+){2}/", "active": True},
    {"type": "regex", "title": "192.168.*.*", "pattern": r"^(http|ws)s?://192\.168(\.\d+){2}/", "active": True},
    {"type": "regex", "title": "1.1.1.*", "pattern": r"^(http|ws)s?://1\.1\.1(\.\d+){1}/", "active": True},
    {"type": "wildcard", "title": "msftconnecttest.com", "pattern": "*msftconnecttest.com*", "active": True},
    {"type": "wildcard", "title": "belling.com.cn", "pattern": "*belling.com.cn*", "active": True},
    {"type": "wildcard", "title": "tuchong.com", "pattern": "*tuchong.com*", "active": True}
]

def get_base_structure():
    """生成 FoxyProxy 配置的基础 JSON 结构"""
    return {
        "mode": "pattern",
        "sync": False,
        "autoBackup": False,
        "passthrough": "",
        "theme": "",
        "container": {},
        "commands": {
            "setProxy": "",
            "setTabProxy": "",
            "includeHost": "",
            "excludeHost": ""
        }
    }

def fetch_gfwlist(url, timeout=10):
    """拉取并解码 gfwlist 内容"""
    print("正在从网络获取最新 gfwlist...")
    req = urllib.request.Request(
        url, 
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode('utf-8')
            return base64.b64decode(content).decode('utf-8')
    except Exception as e:
        print(f"❌ 获取失败: {e}")
        sys.exit(1)

def abp_to_regex(rule):
    """将 ABP 规则精准转换为 FoxyProxy 兼容正则表达式"""
    rule = rule.strip()
    if rule.startswith('/') and rule.endswith('/'):
        return rule[1:-1]
    
    # 域名锚点 ||
    if rule.startswith('||'):
        domain = rule[2:].rstrip('^')
        domain_parts = domain.split('*')
        escaped_parts = [re.escape(part) for part in domain_parts]
        domain_regex = '.*'.join(escaped_parts)
        return r'^https?://(?:[^/]+\.)?' + domain_regex + r'(?:[:/].*|$)'

    # 通用规则转换
    regex = re.escape(rule)
    # 还原 ABP 语法中的特殊字符
    regex = regex.replace(r'\|\|', '||').replace(r'\|', '|').replace(r'\^', '^').replace(r'\*', '*')
    
    if regex.startswith('|'):
        content = regex[1:].rstrip('|')
        return r'^' + content + r'.*'
    elif regex.endswith('|'):
        content = regex.rstrip('|')
        return r'.*' + content + r'$'
    else:
        # ABP 分隔符 ^ -> 非字符/数字/百分号/点/下划线/短横线 或 结尾
        regex = regex.replace('^', r'(?:[^a-zA-Z0-9%._-]|$|(?=/))')
        regex = regex.replace('*', r'.*')
        if not regex.startswith('^') and not regex.startswith('http'):
            regex = r'.*' + regex
        if not regex.endswith('$'):
            regex = regex + r'.*'
        return regex

def convert_abp_rule(rule):
    """智能判断使用 Wildcard（简单通配符）还是 Regex（正则表达式）"""
    rule = rule.strip()
    
    # 1. 显式正则表达式
    if rule.startswith('/') and rule.endswith('/'):
        return "regex", rule[1:-1]
    
    # 2. 域名锚点 (例如 ||google.com^ 或 ||google.com)
    if rule.startswith('||'):
        domain = rule[2:]
        if domain.endswith('^'):
            domain = domain[:-1]
        if not any(c in domain for c in '*|/'):
            return "wildcard", f"*{domain}*"
    
    # 3. 纯字符串/纯域名
    if not any(c in rule for c in '*|^/'):
        return "wildcard", f"*{rule}*"
    
    # 4. 复杂规则回退至正则
    return "regex", abp_to_regex(rule)

def parse_gfwlist(content, custom_include_file=None):
    include_patterns = []
    exclude_patterns = DEFAULT_EXCLUDES.copy()
    
    # 集合（Set）加速去重判断
    seen_include = set()
    seen_exclude = {(item['type'], item['pattern']) for item in exclude_patterns}
    
    dup_count = 0

    # 1. 解析 gfwlist
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue
            
        is_whitelist = line.startswith('@@')
        rule = line[2:] if is_whitelist else line
        
        rule_type, pattern = convert_abp_rule(rule)
        key = (rule_type, pattern)
        pattern_obj = {"type": rule_type, "title": rule, "pattern": pattern, "active": True}
        
        if is_whitelist:
            if key not in seen_exclude:
                seen_exclude.add(key)
                exclude_patterns.append(pattern_obj)
            else:
                dup_count += 1
        else:
            if key not in seen_include:
                seen_include.add(key)
                include_patterns.append(pattern_obj)
            else:
                dup_count += 1
    
    # 2. 解析自定义代理规则文件
    if custom_include_file:
        try:
            with open(custom_include_file, 'r', encoding='utf-8') as f:
                added_count = 0
                custom_dup_count = 0
                for line in f:
                    domain = line.strip()
                    if not domain or domain.startswith('#'):
                        continue
                    
                    rule_type, pattern = convert_abp_rule(domain)
                    key = (rule_type, pattern)
                    if key not in seen_include:
                        seen_include.add(key)
                        include_patterns.append({
                            "type": rule_type,
                            "title": f"Custom: {domain}",
                            "pattern": pattern,
                            "active": True
                        })
                        added_count += 1
                    else:
                        custom_dup_count += 1
            print(f"✅ 已从 {custom_include_file} 新增 {added_count} 条自定义规则（跳过 {custom_dup_count} 条重复）。")
        except FileNotFoundError:
            print(f"ℹ️ 未找到自定义文件 {custom_include_file}，仅使用 gfwlist。")
        except Exception as e:
            print(f"⚠️ 读取自定义列表出错: {e}")
            
    if dup_count > 0:
        print(f"ℹ️ gfwlist 中去重了 {dup_count} 条重复规则。")

    return include_patterns, exclude_patterns

def generate_foxyproxy_json(include_patterns, exclude_patterns, proxy_host, proxy_port, proxy_type, title):
    config = get_base_structure()
    config["data"] = [
        {
            "active": True,
            "title": title,
            "type": proxy_type.lower(),
            "hostname": proxy_host,
            "port": str(proxy_port),
            "username": "",
            "password": "",
            "cc": "",
            "city": "",
            "color": "#0080ff",
            "pac": "",
            "pacString": "",
            "proxyDNS": True,
            "include": include_patterns,
            "exclude": exclude_patterns,
            "tabProxy": []
        }
    ]
    return config

def main():
    current_date = datetime.now().strftime("%Y-%m-%d")
    default_output = f"FoxyProxy_{current_date}.json"

    parser = argparse.ArgumentParser(description="gfwlist 转换为 FoxyProxy 配置文件工具")
    parser.add_argument("-o", "--output", default=default_output, help=f"输出文件名 (默认: {default_output})")
    parser.add_argument("--host", default="127.0.0.1", help="代理地址")
    parser.add_argument("--port", default="10808", help="代理端口")
    parser.add_argument("--type", default="socks5", choices=["http", "https", "socks4", "socks5"], help="代理协议")
    parser.add_argument("--title", default="auto", help="配置节点名称")
    parser.add_argument("--include-file", default="new_list.txt", help="自定义代理域名列表")
    args = parser.parse_args()

    content = fetch_gfwlist(GFWLIST_URL)
    inc, exc = parse_gfwlist(content, args.include_file)
    config = generate_foxyproxy_json(inc, exc, args.host, args.port, args.type, args.title)
    
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"\n🎉 转换成功！")
        print(f"📄 输出文件: {args.output}")
        print(f"📊 统计: 代理 (Include) {len(inc)} 条 | 直连 (Exclude) {len(exc)} 条")
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")

if __name__ == "__main__":
    main()
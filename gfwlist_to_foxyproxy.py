import base64
import json
import re
import urllib.request
import argparse
import sys
import time
from datetime import datetime

# gfwlist 官方源
GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

# --- 基础配置硬编码 ---
# 默认直连规则 (Exclude)
DEFAULT_EXCLUDES = [
    {"type": "regex", "title": "10.*.*.*", "pattern": r"^(http|ws)s?://10(\.\d+){3}/", "active": True},
    {"type": "regex", "title": "127.*.*.*", "pattern": r"^(http|ws)s?://127(\.\d+){3}/", "active": True},
    {"type": "regex", "title": "172.16.*.*", "pattern": r"^(http|ws)s?://172\.16(\.\d+){2}/", "active": True},
    {"type": "regex", "title": "192.168.*.*", "pattern": r"^(http|ws)s?://192\\.168(\\.\\d+){2}/", "active": True},
    {"type": "regex", "title": "1.1.1.*", "pattern": r"^(http|ws)s?://1\.1\.1(\.\d+){1}/", "active": True},
    {"type": "wildcard", "title": "msftconnecttest.com", "pattern": "*msftconnecttest.com*", "active": True},
    {"type": "wildcard", "title": "belling.com.cn", "pattern": "*belling.com.cn*", "active": True},
    {"type": "wildcard", "title": "tuchong.com", "pattern": "*tuchong.com*", "active": True}
]

# FoxyProxy 基础结构
def get_base_structure():
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

def fetch_gfwlist(url):
    print(f"正在从网络获取最新 gfwlist...")
    try:
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            return base64.b64decode(content).decode('utf-8')
    except Exception as e:
        print(f"获取失败: {e}")
        sys.exit(1)

def abp_to_regex(rule):
    """
    将 ABP 规则转换为 FoxyProxy 兼容的高精度正则表达式
    """
    rule = rule.strip()
    if rule.startswith('/') and rule.endswith('/'):
        return rule[1:-1]
    regex = re.escape(rule)
    regex = regex.replace(r'\|\|', '||').replace(r'\|', '|').replace(r'\^', '^').replace(r'\*', '*')
    
    if regex.startswith('||'):
        domain = regex[2:].split('^')[0]
        return r'^https?://(?:[^/]+\.)?' + domain + r'(?:[:/].*|$)'
    elif regex.startswith('|'):
        content = regex[1:].rstrip('|')
        return r'^' + content + r'.*'
    elif regex.endswith('|'):
        content = regex.rstrip('|')
        return r'.*' + content + r'$'
    else:
        regex = regex.replace('^', r'(?:[^a-zA-Z0-9%._-]|$|(?=/))')
        regex = regex.replace('*', r'.*')
        if not regex.startswith('^') and not regex.startswith('http'):
            regex = r'.*' + regex
        if not regex.endswith('$'):
            regex = regex + r'.*'
        return regex

def convert_abp_rule(rule):
    """
    根据规则复杂度智能选择 wildcard 或 regex
    """
    rule = rule.strip()
    
    # 1. 显式正则表达式
    if rule.startswith('/') and rule.endswith('/'):
        return "regex", rule[1:-1]
    
    # 2. 域名锚点 (例如 ||google.com^ 或 ||google.com)
    if rule.startswith('||'):
        domain = rule[2:]
        if domain.endswith('^'):
            domain = domain[:-1]
        # 如果提取出的域名中没有其他通配符或特殊字符，使用通配符模式
        if not any(c in domain for c in '*|/'):
            return "wildcard", f"*{domain}*"
    
    # 3. 没有任何特殊字符的纯域名/字符串
    if not any(c in rule for c in '*|^/'):
        return "wildcard", f"*{rule}*"
    
    # 4. 其他复杂情况使用原有的高精度正则转换
    return "regex", abp_to_regex(rule)

def parse_gfwlist(content, custom_include_file=None):
    include_patterns = []
    exclude_patterns = DEFAULT_EXCLUDES.copy() # 使用硬编码的默认直连规则
    
    # 1. 解析 gfwlist 规则
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['): continue
        is_whitelist = line.startswith('@@')
        rule = line[2:] if is_whitelist else line
        
        rule_type, pattern = convert_abp_rule(rule)
        pattern_obj = {"type": rule_type, "title": rule, "pattern": pattern, "active": True}
        
        if is_whitelist: exclude_patterns.append(pattern_obj)
        else: include_patterns.append(pattern_obj)
    
    # 2. 读取并加入 new_list.txt 里的自定义代理规则 (Include)
    if custom_include_file:
        try:
            with open(custom_include_file, 'r', encoding='utf-8') as f:
                count = 0
                for line in f:
                    domain = line.strip()
                    if domain:
                        rule_type, pattern = convert_abp_rule(domain)
                        include_patterns.append({
                            "type": rule_type,
                            "title": f"Custom: {domain}",
                            "pattern": pattern,
                            "active": True
                        })
                        count += 1
            print(f"✅ 已从 {custom_include_file} 追加了 {count} 条代理规则。")
        except FileNotFoundError:
            print(f"ℹ️ 未发现自定义列表文件 {custom_include_file}，将只转换 gfwlist。")
            
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
    # 获取当前日期用于默认文件名
    current_date = datetime.now().strftime("%Y-%m-%d")
    default_output = f"FoxyProxy_{current_date}.json"

    parser = argparse.ArgumentParser(description="自包含的 gfwlist 到 FoxyProxy 转换脚本")
    parser.add_argument("-o", "--output", default=default_output, help=f"输出文件名 (默认: {default_output})")
    parser.add_argument("--host", default="127.0.0.1", help="代理地址")
    parser.add_argument("--port", default="10808", help="代理端口")
    parser.add_argument("--type", default="socks5", choices=["http", "https", "socks4", "socks5"], help="代理类型")
    parser.add_argument("--title", default="auto", help="代理配置名称")
    parser.add_argument("--include-file", default="new_list.txt", help="自定义代理域名文件")
    args = parser.parse_args()

    content = fetch_gfwlist(GFWLIST_URL)
    inc, exc = parse_gfwlist(content, args.include_file)
    config = generate_foxyproxy_json(inc, exc, args.host, args.port, args.type, args.title)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n🎉 转换完成！")
    print(f"结果文件: {args.output}")
    print(f"规则统计: {len(inc)} 条代理 (Include), {len(exc)} 条直连 (Exclude)")

if __name__ == "__main__":
    main()

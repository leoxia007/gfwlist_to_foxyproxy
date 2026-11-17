#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import json
import os
import re
import sys
import urllib.request
from datetime import datetime

# 官方源及加速镜像源（主源失败自动降级重试）
GFWLIST_URLS = [
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
    "https://fastly.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt",
    "https://cdn.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt",
]

# 完善的局域网 & 私有地址放行规则 (RFC 1918, RFC 3927, RFC 4193 等)
DEFAULT_EXCLUDES = [
    {"type": "regex", "title": "Localhost / Loopback", "pattern": r"^(http|ws)s?://(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?/", "active": True},
    {"type": "regex", "title": "Private: 10.0.0.0/8", "pattern": r"^(http|ws)s?://10(\.\d+){3}(:\d+)?/", "active": True},
    {"type": "regex", "title": "Private: 172.16.0.0/12", "pattern": r"^(http|ws)s?://172\.(1[6-9]|2\d|3[01])(\.\d+){2}(:\d+)?/", "active": True},
    {"type": "regex", "title": "Private: 192.168.0.0/16", "pattern": r"^(http|ws)s?://192\.168(\.\d+){2}(:\d+)?/", "active": True},
    {"type": "regex", "title": "Carrier NAT: 100.64.0.0/10", "pattern": r"^(http|ws)s?://100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])(\.\d+){2}(:\d+)?/", "active": True},
    {"type": "wildcard", "title": "Captive Portal: msftconnecttest", "pattern": "*msftconnecttest.com*", "active": True},
    {"type": "wildcard", "title": "Captive Portal: captive.apple.com", "pattern": "*captive.apple.com*", "active": True},
    {"type": "wildcard", "title": "Common Local: *.local", "pattern": "*.local*", "active": True},
    {"type": "wildcard", "title": "Common Local: *.lan", "pattern": "*.lan*", "active": True},
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


def fetch_gfwlist(urls, proxy_env=None, timeout=12):
    """
    拉取并解码 gfwlist 内容
    支持 HTTP 代理与多源轮询降级
    """
    handlers = []
    if proxy_env:
        print(f"🌐 使用网络代理拉取规则: {proxy_env}")
        handlers.append(urllib.request.ProxyHandler({'http': proxy_env, 'https': proxy_env}))
    
    opener = urllib.request.build_opener(*handlers)
    opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")]
    
    for url in urls:
        print(f"正在从网络源拉取: {url} ...")
        try:
            with opener.open(url, timeout=timeout) as response:
                content = response.read().decode('utf-8')
                # 修复可能缺失的 Base64 Padding
                missing_padding = len(content) % 4
                if missing_padding:
                    content += '=' * (4 - missing_padding)
                return base64.b64decode(content).decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"⚠️ 当前节点拉取失败 ({e})，尝试下一备用源...")

    print("❌ 所有在线网络源均拉取失败！可指定 --input 本地文件直接转换。")
    sys.exit(1)


def abp_to_regex(rule):
    """
    将 ABP 语法严谨转化为正则表达式
    修复原脚本中 startswith('|') 导致中途 return 跳过后续转义的 Bug
    """
    rule = rule.strip()
    
    # 显式正则表达式: /pattern/
    if rule.startswith('/') and rule.endswith('/'):
        return rule[1:-1]

    # 1. 处理以 || 开头的域名匹配 (匹配当前域及任意子域名)
    if rule.startswith('||'):
        domain = rule[2:].rstrip('^')
        # 将通配符 * 分段转义
        parts = [re.escape(p) for p in domain.split('*')]
        domain_pattern = '.*'.join(parts)
        return rf"^https?://(?:[^/:]+\.)?{domain_pattern}(?:[:/].*|$)"

    # 2. 全局通用转义处理
    # 预留 ABP 特殊元字符，转义常规正则保留字符
    specials = {'||': '__ABP_DOMAIN__', '|': '__ABP_ANCHOR__', '^': '__ABP_SEP__', '*': '__ABP_STAR__'}
    for sym, token in specials.items():
        rule = rule.replace(sym, token)

    regex = re.escape(rule)

    # 还原并精准转为正则表达式
    regex = regex.replace('__ABP_DOMAIN__', r'^https?://(?:[^/:]+\.)?')
    regex = regex.replace('__ABP_STAR__', r'.*')
    # 分隔符 ^: 匹配非字符数字/百分号/点/短横 或 端口斜杠结尾
    regex = regex.replace('__ABP_SEP__', r'(?:[^a-zA-Z0-9%._-]|$|(?=[/:?#]))')

    # 处理开头 | 和结尾 |
    if regex.startswith('__ABP_ANCHOR__'):
        regex = '^' + regex[len('__ABP_ANCHOR__'):]
    else:
        if not regex.startswith('^'):
            regex = r'.*' + regex

    if regex.endswith('__ABP_ANCHOR__'):
        regex = regex[:-len('__ABP_ANCHOR__')] + '$'
    else:
        if not regex.endswith('$'):
            regex = regex + r'.*'

    # 清理残留标记（若规则中间有 |）
    regex = regex.replace('__ABP_ANCHOR__', '|')
    return regex


def convert_abp_rule(rule):
    """
    智能选择 Wildcard 还是 Regex:
    防止短域名 (如 x.com, t.co) 产生大范围误匹配
    """
    rule = rule.strip()

    # 正则表达式直接使用 regex
    if rule.startswith('/') and rule.endswith('/'):
        return "regex", rule[1:-1]

    # || 开头的域名锚点规则
    if rule.startswith('||'):
        domain = rule[2:]
        if domain.endswith('^'):
            domain = domain[:-1]

        # 防误杀设计：如果域名较短或包含特殊通配符，使用正则精准界定
        # 只有普通且长度足够的主机名，转通配符才安全
        if not any(c in domain for c in '*|/'):
            root_sld = domain.split('.')[0] if '.' in domain else domain
            if len(root_sld) >= 5:  # 长度足够，不易发生子串误杀
                return "wildcard", f"*{domain}*"
            else:
                # 短域名（如 t.co, x.com）强制走精确正则，防止匹配到 contest.com
                return "regex", rf"^https?://(?:[^/:]+\.)?{re.escape(domain)}(?:[:/].*|$)"

    # 纯域名或文本且不包含特殊字符
    if not any(c in rule for c in '*|^/'):
        if '.' in rule and len(rule.split('.')[0]) >= 5:
            return "wildcard", f"*{rule}*"
        return "regex", rf"^https?://(?:[^/:]+\.)?{re.escape(rule)}(?:[:/].*|$)"

    # 复杂规则使用正则转换
    return "regex", abp_to_regex(rule)


def parse_gfwlist(content, custom_include_file=None):
    """解析规则集并去重"""
    include_patterns = []
    exclude_patterns = DEFAULT_EXCLUDES.copy()

    seen_include = set()
    seen_exclude = {(item['type'], item['pattern']) for item in exclude_patterns}
    dup_count = 0

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

    # 解析用户自定义文件
    if custom_include_file and os.path.exists(custom_include_file):
        try:
            added = 0
            with open(custom_include_file, 'r', encoding='utf-8') as f:
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
                        added += 1
            print(f"✅ 已从 {custom_include_file} 载入 {added} 条自定义规则。")
        except Exception as e:
            print(f"⚠️ 读取自定义列表失败: {e}")

    if dup_count > 0:
        print(f"ℹ️ 自动去除重复规则 {dup_count} 条。")

    return include_patterns, exclude_patterns


def generate_foxyproxy_json(include_patterns, exclude_patterns, proxy_host, proxy_port, proxy_type, title):
    """装配 FoxyProxy JSON"""
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

    parser = argparse.ArgumentParser(description="GFWList 转换为 FoxyProxy 配置优化版")
    parser.add_argument("-o", "--output", default=default_output, help=f"输出文件名 (默认: {default_output})")
    parser.add_argument("-i", "--input", help="本地 gfwlist.txt 文件路径 (跳过在线下载)")
    parser.add_argument("--proxy", help="下载 gfwlist 时使用的代理 (例如: http://127.0.0.1:7890)")
    parser.add_argument("--host", default="127.0.0.1", help="代理服务器地址 (默认: 127.0.0.1)")
    parser.add_argument("--port", default="10808", help="代理端口 (默认: 10808)")
    parser.add_argument("--type", default="socks5", choices=["http", "https", "socks4", "socks5"], help="代理协议 (默认: socks5)")
    parser.add_argument("--title", default="auto", help="配置节点名称")
    parser.add_argument("--include-file", default="new_list.txt", help="自定义追加的域名列表 (默认: new_list.txt)")
    args = parser.parse_args()

    # 1. 获取源内容
    if args.input:
        if not os.path.isfile(args.input):
            print(f"❌ 指定的本地文件不存在: {args.input}")
            sys.exit(1)
        print(f"📖 正在从本地读取规则文件: {args.input} ...")
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # 兼容如果本地文件也是 Base64 编码的情况
            if not content.startswith('!') and not content.startswith('['):
                try:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
                except Exception:
                    pass
    else:
        content = fetch_gfwlist(GFWLIST_URLS, proxy_env=args.proxy)

    # 2. 转换规则
    inc, exc = parse_gfwlist(content, args.include_file)
    config = generate_foxyproxy_json(inc, exc, args.host, args.port, args.type, args.title)

    # 3. 输出文件
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"\n🎉 转换生成成功！")
        print(f"📄 配置文件: {os.path.abspath(args.output)}")
        print(f"📊 规则统计: 代理 (Include) {len(inc)} 条 | 直连 (Exclude) {len(exc)} 条")
    except Exception as e:
        print(f"❌ 写入文件失败: {e}")


if __name__ == "__main__":
    main()
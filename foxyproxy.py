import requests
import base64
import json
import re
import os
import datetime
import argparse

# --- 配置 ---
GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
DEFAULT_OUTPUT_FILENAME = "FoxyProxy.json"
NEW_URLS_FILENAME = "new_list.txt"
# ---------------------

def fetch_and_decode_gfwlist(url):
    """
    从指定的 URL 获取 gfwlist 并进行 Base64 解码。
    """
    print(f"正在从以下地址获取 gfwlist: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        decoded_content = base64.b64decode(response.text).decode('utf-8')
        return decoded_content
    except requests.RequestException as e:
        print(f"获取 gfwlist 时出错: {e}")
        return None
    except base64.binascii.Error as e:
        print(f"解码 Base64 内容时出错: {e}")
        return None

def convert_rule_to_pattern(rule):
    """
    将 gfwlist 规则转换为 FoxyProxy 通配符模式，并提取域名作为标题。
    """
    processed_rule = re.sub(r'^(?:\|\||\.)', '', rule)
    processed_rule = processed_rule.replace('^', '')
    domain_part = re.split(r'[/?\*]', processed_rule)[0]

    if not domain_part or '.' not in domain_part:
        return None, None

    pattern = f"*{domain_part}*"
    title = domain_part
    return pattern, title

def generate_gfw_patterns(gfwlist_content):
    """
    处理 gfwlist 内容并生成 FoxyProxy 模式。
    """
    patterns = []
    if not gfwlist_content:
        return patterns

    rules = gfwlist_content.splitlines()
    processed_patterns = set()
    print(f"正在处理来自 gfwlist 的 {len(rules)} 条规则...")

    for rule in rules:
        rule = rule.strip()
        if not rule or rule.startswith(('!', '@@', '[')):
            continue

        pattern, title = convert_rule_to_pattern(rule)
        if pattern and pattern not in processed_patterns:
            patterns.append({
                "type": "wildcard",
                "title": title,
                "pattern": pattern,
                "active": True
            })
            processed_patterns.add(pattern)
    return patterns

def create_base_config():
    """
    创建 FoxyProxy 配置的基本结构。
    """
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
        },
        "data": [
            {
                "active": True,
                "title": "auto",
                "type": "socks5",
                "hostname": "127.0.0.1",
                "port": "10808",
                "username": "",
                "password": "",
                "cc": "",
                "city": "",
                "color": "#0080ff",
                "pac": "",
                "pacString": "",
                "proxyDNS": True,
                "include": [],
                "exclude": [
                    {"type": "regex", "title": "10.*.*.*", "pattern": "^(http|ws)s?://10(\\.\\d+){3}/", "active": True},
                    {"type": "regex", "title": "127.*.*.*", "pattern": "^(http|ws)s?://127(\\.\\d+){3}/", "active": True},
                    {"type": "regex", "title": "172.16.*.*", "pattern": "^(http|ws)s?://172\\.16(\\.\\d+){2}/", "active": True},
                    {"type": "regex", "title": "192.168.*.*", "pattern": "^(http|ws)s?://192\\.168(\\.\\d+){2}/", "active": True},
                    {"type": "regex", "title": "1.1.1.*", "pattern": "^(http|ws)s?://1\\.1\\.1(\\.\\d+){1}/", "active": True},
                    {"type": "wildcard", "title": "msftconnecttest.com", "pattern": "*msftconnecttest.com*", "active": True},
                    {"type": "wildcard", "title": "belling.com.cn", "pattern": "*belling.com.cn*", "active": True},
                    {"type": "wildcard", "title": "tuchong.com", "pattern": "*tuchong.com*", "active": True},
                ],
                "tabProxy": []
            }
        ]
    }

def add_custom_rules_from_file(config, urls_filepath):
    """
    从文件向配置中添加自定义 URL 规则。
    """
    try:
        with open(urls_filepath, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"成功从 '{urls_filepath}' 读取 {len(urls)} 个 URL。")
    except FileNotFoundError:
        print(f"信息: 自定义规则文件 '{urls_filepath}' 未找到。正在跳过。")
        return config

    existing_patterns = {item['pattern'] for item in config['data'][0]['include']}
    added_count = 0

    for url in urls:
        pattern, title = convert_rule_to_pattern(url)

        if pattern and title and pattern not in existing_patterns:
            new_rule = {"type": "wildcard", "title": title, "pattern": pattern, "active": True}
            config['data'][0]['include'].append(new_rule)
            existing_patterns.add(pattern)
            added_count += 1
            print(f"已添加新的自定义规则: '{title}'")
        elif pattern in existing_patterns:
            print(f"跳过已存在的自定义规则: '{title}'")
        else:
            print(f"无法处理无效的自定义规则: '{url}'")

    print(f"已添加 {added_count} 条新的自定义规则。")
    return config

def save_config_to_file(config, filename):
    """
    将最终配置保存到 JSON 文件。
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"成功将配置保存到 '{os.path.abspath(filename)}'")
    except IOError as e:
        print(f"保存文件时出错: {e}")

def main():
    parser = argparse.ArgumentParser(description="FoxyProxy 规则管理器")
    parser.add_argument(
        '--update-gfw',
        action='store_true',
        help="从 gfwlist 更新规则。"
    )
    parser.add_argument(
        '--add-custom',
        action='store_true',
        help=f"从 '{NEW_URLS_FILENAME}' 添加自定义规则。"
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help=f"输出文件名。默认为 '{DEFAULT_OUTPUT_FILENAME}' 或在未指定操作时使用带时间戳的文件。"
    )
    args = parser.parse_args()

    # 如果未指定特定操作，则执行默认的完全更新
    perform_full_update = not (args.update_gfw or args.add_custom)

    config = create_base_config()
    gfw_patterns = []

    if args.update_gfw or perform_full_update:
        gfwlist_content = fetch_and_decode_gfwlist(GFWLIST_URL)
        if gfwlist_content:
            gfw_patterns = generate_gfw_patterns(gfwlist_content)
            
            # 分离 x.com 模式
            x_com_patterns = [p for p in gfw_patterns if p.get('title') == 'x.com']
            other_patterns = [p for p in gfw_patterns if p.get('title') != 'x.com']
            
            # 首先添加其他模式，然后添加 x.com 模式
            config['data'][0]['include'].extend(other_patterns)
            config['data'][0]['include'].extend(x_com_patterns)
            
            print(f"已从 gfwlist 生成并排序 {len(gfw_patterns)} 个模式。")

    if args.add_custom or perform_full_update:
        config = add_custom_rules_from_file(config, NEW_URLS_FILENAME)

    # 确定输出文件名
    output_filename = args.output
    if output_filename is None:
        if perform_full_update:
             today_str = datetime.date.today().strftime("%Y-%m-%d")
             output_filename = f"FoxyProxy_{today_str}.json"
        else:
             output_filename = DEFAULT_OUTPUT_FILENAME

    save_config_to_file(config, output_filename)

if __name__ == "__main__":
    main()
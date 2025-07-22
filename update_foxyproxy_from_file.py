import json
import datetime
import os

def update_foxyproxy_config_from_file(input_filepath="FoxyProxy.json", new_urls_filepath="new_list.txt"):
    """
    智能更新 FoxyProxy 配置文件，从指定文件读取网址并添加新的包含规则，
    并跳过已经存在的规则。

    Args:
        input_filepath (str): 现有 FoxyProxy 配置文件的路径。
        new_urls_filepath (str): 包含新增网址的文本文件路径，每行一个网址。
    """
    # 1. 尝试加载现有配置文件
    config_data = None
    try:
        with open(input_filepath, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        print(f"成功加载现有配置文件：'{input_filepath}'")
    except FileNotFoundError:
        print(f"警告：找不到 '{input_filepath}'。将创建一个新的配置。")
        # 如果文件不存在，创建一个基础的 FoxyProxy 结构
        config_data = {
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
                        {
                            "type": "regex",
                            "title": "10.*.*.*",
                            "pattern": "^(http|ws)s?://10(\\.\\d+){3}/",
                            "active": True
                        },
                        {
                            "type": "regex",
                            "title": "127.*.*.*",
                            "pattern": "^(http|ws)s?://127(\\.\\d+){3}/",
                            "active": True
                        },
                        {
                            "type": "regex",
                            "title": "172.16.*.*",
                            "pattern": "^(http|ws)s?://172\\.16(\\.\\d+){2}/",
                            "active": True
                        },
                        {
                            "type": "regex",
                            "title": "192.168.*.*",
                            "pattern": "^(http|ws)s?://192\\.168(\\.\\d+){2}/",
                            "active": True
                        },
                        {
                            "type": "regex",
                            "title": "1.1.1.*",
                            "pattern": "^(http|ws)s?://1\\.1\\.1(\\.\\d+){1}/",
                            "active": True
                        },
                        {
                            "type": "wildcard",
                            "title": "msftconnecttest.com",
                            "pattern": "*msftconnecttest.com*",
                            "active": True
                        }
                    ],
                    "tabProxy": []
                }
            ]
        }
    except json.JSONDecodeError:
        print(f"错误：无法解析文件 '{input_filepath}' 中的 JSON。请确保它是有效的 JSON 格式。")
        return

    # 确保 'data' 和 'data[0]' 以及 'include' 结构存在
    if not isinstance(config_data.get('data'), list) or not config_data['data']:
        print("错误：FoxyProxy 配置缺少 'data' 列表或其内容。")
        return
    if not isinstance(config_data['data'][0].get('include'), list):
        print("错误：FoxyProxy 配置中第一个数据项缺少 'include' 列表。")
        return

    # 2. 从 new_urls_filepath 读取网址列表
    urls = []
    try:
        with open(new_urls_filepath, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:  # 忽略空行
                    urls.append(stripped_line)
        print(f"成功从文件 '{new_urls_filepath}' 读取网址。")
    except FileNotFoundError:
        print(f"错误：找不到新增网址文件 '{new_urls_filepath}'。请确保文件存在。")
        return
    except Exception as e:
        print(f"读取文件 '{new_urls_filepath}' 时发生错误：{e}")
        return

    if not urls:
        print("新增网址文件中没有内容，操作取消。")
        return

    # 3. 为每个网址添加或更新规则
    # 使用集合来存储现有规则的 pattern，以便快速查找和判断是否存在
    existing_patterns = {item['pattern'] for item in config_data['data'][0]['include']}
    added_count = 0

    print("\n--- 处理网址 ---")
    for url in urls:
        # 提取域名作为 title，并生成通配符 pattern
        # 简单处理：如果输入的是完整URL，只取域名部分
        if '://' in url:
            domain = url.split('://', 1)[1].split('/')[0]
        else:
            domain = url.split('/')[0] # 假设输入是像 example.com 或 example.com/path 这样的
        
        # 移除端口号
        if ':' in domain:
            domain = domain.split(':')[0]

        pattern = f"*{domain}*"
        title = domain

        # 关键改进：判断规则是否已存在
        if pattern not in existing_patterns:
            new_rule = {
                "type": "wildcard",
                "title": title,
                "pattern": pattern,
                "active": True
            }
            config_data['data'][0]['include'].append(new_rule)
            existing_patterns.add(pattern) # 更新已存在模式集合
            added_count += 1
            print(f"✅ 已添加新规则：Title='{title}', Pattern='{pattern}'")
        else:
            print(f"ℹ️ 规则已存在，跳过：Title='{title}', Pattern='{pattern}'")

    if added_count == 0:
        print("\n没有新的规则被添加。文件未修改。")
        return

    # 4. 生成带日期的输出文件名
    # 使用当前日期，2025年7月16日
    today_str = datetime.date.today().strftime("%Y-%m-%d") 
    output_filepath = f"FoxyProxy_{today_str}.json"

    # 5. 将更新后的数据保存到新文件
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        print(f"\n🎉 成功将更新后的配置保存到：'{output_filepath}'")
    except IOError:
        print(f"❌ 错误：无法写入输出文件 '{output_filepath}'。")

def main():
    # 定义输入和新增网址文件的路径
    foxyproxy_config_file = 'FoxyProxy.json'
    new_urls_file = 'new_list.txt'
    
    update_foxyproxy_config_from_file(foxyproxy_config_file, new_urls_file)

# --- 脚本执行 ---
if __name__ == "__main__":
    main()
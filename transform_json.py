import json

def transform_json_file(input_filepath, output_filepath):
    """
    读取 input.json 文件，转换其内容，然后将转换后的数据写入 output.json 文件。

    Args:
        input_filepath (str): 输入 JSON 文件的路径。
        output_filepath (str): 输出 JSON 文件的路径。
    """
    try:
        with open(input_filepath, 'r', encoding='utf-8') as f:
            original_json_list = json.load(f)
    except FileNotFoundError:
        print(f"错误：找不到输入文件 '{input_filepath}'。")
        return
    except json.JSONDecodeError:
        print(f"错误：无法解析文件 '{input_filepath}' 中的 JSON。请确保它是有效的 JSON 格式。")
        return

    transformed_data = {
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
                    },
                    {
                        "type": "wildcard",
                        "title": "belling.com.cn",
                        "pattern": "*belling.com.cn*",
                        "active": True
                    }
                ],
                "tabProxy": []
            }
        ]
    }

    # 遍历原始 JSON 列表，提取相关信息并添加到 'include' 列表中
    for item in original_json_list:
        new_include_item = {
            "type": item["type"],
            "title": item["title"],
            "pattern": item["pattern"],
            "active": item["active"]
        }
        transformed_data["data"][0]["include"].append(new_include_item)

    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            json.dump(transformed_data, f, indent=2, ensure_ascii=False)
        print(f"成功将数据从 '{input_filepath}' 转换为 '{output_filepath}'。")
    except IOError:
        print(f"错误：无法写入输出文件 '{output_filepath}'。")

def main():
    # 定义文件路径
    input_file = 'foxyproxy_patterns.json'
    output_file = 'FoxyProxy.json'

    # 调用函数执行转换
    transform_json_file(input_file, output_file)
    
if __name__ == "__main__":
    main()
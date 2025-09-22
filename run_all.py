import gfwlist_to_foxproxy
import transform_json
import update_foxyproxy_from_file
import shutil,os


def main():
    gfwlist_to_foxproxy.main()
    transform_json.main()
    update_foxyproxy_from_file.main()
    shutil.rmtree("__pycache__")
    os.remove("FoxyProxy.json")
    os.remove("foxyproxy_patterns.json")
    
if __name__ == "__main__":
    main()
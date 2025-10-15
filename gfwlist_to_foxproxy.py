import requests
import base64
import json
import re
import os

# --- Configuration ---
# gfwlist 的 URL
GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
# 输出文件名
OUTPUT_FILE = "foxyproxy_patterns.json"
# ---------------------

def fetch_and_decode_gfwlist(url):
    """
    Fetch the gfwlist from the URL and decode it from Base64.
    """
    print(f"Fetching gfwlist from: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()

        # gfwlist content is Base64 encoded
        decoded_content = base64.b64decode(response.text).decode('utf-8')
        return decoded_content

    except requests.RequestException as e:
        print(f"Error fetching gfwlist: {e}")
        return None
    except base64.binascii.Error as e:
        print(f"Error decoding Base64 content: {e}")
        return None

def convert_rule_to_pattern(rule):
    """
    Convert a gfwlist rule into a FoxyProxy wildcard pattern and extract the domain for the title.
    Returns (pattern, title) tuple.
    """
    # Remove leading '||' (domain match) or '.' (suffix match)
    processed_rule = re.sub(r'^(?:\|\||\.)', '', rule)
    
    # Remove '^' (end of address)
    processed_rule = processed_rule.replace('^', '')
    
    # Extract the domain part by splitting at common path/query delimiters
    domain_part = re.split(r'[/?\*]', processed_rule)[0]

    # Validate that we extracted something resembling a domain
    if not domain_part or '.' not in domain_part:
        return None, None

    # FoxyProxy wildcard format: *domain.com*
    pattern = f"*{domain_part}*"
    # Use the extracted domain as the title
    title = domain_part

    return pattern, title
def generate_foxyproxy_patterns(gfwlist_content):
    """
    Process the gfwlist content and generate FoxyProxy patterns in the requested format.
    """
    patterns = []
    
    if not gfwlist_content:
        return patterns

    rules = gfwlist_content.splitlines()
    processed_patterns = set()

    print(f"Processing {len(rules)} rules...")
    
    for rule in rules:
        rule = rule.strip()
        
        # --- EXCLUSION LOGIC ---
        # 1. Ignore headers like [AutoProxy 0.2.9]
        if rule.startswith('[') and rule.endswith(']'):
            continue
            
        # 2. Ignore comments ('!') and exclusion rules ('@@') and empty lines
        if not rule or rule.startswith('!') or rule.startswith('@@'):
            continue
        # -----------------------
            
        pattern, title = convert_rule_to_pattern(rule)

        if pattern and pattern not in processed_patterns:
            # Create the pattern object in the requested format
            patterns.append({
                "include": "include",
                "type": "wildcard",
                "title": title,
                "pattern": pattern,
                "active": True
            })
            processed_patterns.add(pattern)

    return patterns

def main():
    # 1. Fetch and decode gfwlist
    gfwlist_content = fetch_and_decode_gfwlist(GFWLIST_URL)
    if not gfwlist_content:
        return

    # 2. Generate FoxyProxy patterns
    foxyproxy_patterns = generate_foxyproxy_patterns(gfwlist_content)

    if not foxyproxy_patterns:
        print("No valid patterns generated.")
        return

    # Move patterns with title 'x.com' to the end
    x_com_patterns = [p for p in foxyproxy_patterns if p['title'] == 'x.com']
    other_patterns = [p for p in foxyproxy_patterns if p['title'] != 'x.com']
    foxyproxy_patterns = other_patterns + x_com_patterns

    print(f"Successfully generated {len(foxyproxy_patterns)} FoxyProxy patterns.")

    # 3. Save the patterns to a JSON file
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(foxyproxy_patterns, f, ensure_ascii=False, indent=4)
        
        print(f"Patterns saved to {os.path.abspath(OUTPUT_FILE)}")
    except IOError as e:
        print(f"Error saving file: {e}")

if __name__ == "__main__":
    main()
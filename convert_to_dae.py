import os

SOURCE_DIR = "List"
OUTPUT_DIR = "daed_List"

def convert_line(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('//'):
        return None
    
    parts = [p.strip() for p in line.split(',')]
    if len(parts) < 2:
        return None

    rule_type = parts[0].upper()
    val = parts[1]

    if rule_type == 'DOMAIN':
        return f"domain(full: {val})"
    elif rule_type == 'DOMAIN-SUFFIX':
        return f"domain(suffix: {val})"
    elif rule_type == 'DOMAIN-KEYWORD':
        return f"domain(keyword: {val})"
    elif rule_type in ('IP-CIDR', 'IP-CIDR6'):
        return f"ip({val})"
    elif rule_type == 'PROCESS-NAME':
        return f"process(name: {val})"
    elif rule_type == 'USER-AGENT':
        return f"ua(keyword: {val})"
    
    return None

def main():
    for root, _, files in os.walk(SOURCE_DIR):
        for file in files:
            if file.endswith(('.list', '.txt')):
                src_path = os.path.join(root, file)
                
                # 计算相对路径，保持目录结构一致
                rel_path = os.path.relpath(src_path, SOURCE_DIR)
                dest_path = os.path.join(OUTPUT_DIR, rel_path)
                
                # 更改拓展名为 .dae 或保留 .list
                dest_path = os.path.splitext(dest_path)[0] + ".dae"
                
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                converted_rules = []
                with open(src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        res = convert_line(line)
                        if res:
                            converted_rules.append(res)
                
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write("# Auto-generated daed ruleset\n")
                    f.write("\n".join(converted_rules) + "\n")
                
                print(f"Converted: {src_path} -> {dest_path}")

if __name__ == "__main__":
    main()

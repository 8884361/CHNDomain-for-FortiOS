#!/usr/bin/env python3
import requests
from pathlib import Path
from datetime import datetime

# ================================
# Working directory (.github)
# ================================
WORKDIR = Path.cwd()
OUTPUT_DIR = WORKDIR / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ================================
# Source URL
# ================================
DOMAIN_URL = "https://github.com/blackmatrix7/ios_rule_script/raw/refs/heads/master/rule/Clash/China/China_Domain.txt"

# ================================
# Constants
# ================================
CHUNK_SIZE = 600
TODAY = datetime.now().strftime("%Y-%m-%d")

# ================================
# Fetch domain list
# ================================
def fetch_domains():
    try:
        r = requests.get(DOMAIN_URL, timeout=10)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Error fetching domain list: {e}")
        return []

# ================================
# Normalize domain rules
# ================================
def normalize_domain(line):
    line = line.strip()

    if not line or line.startswith("#"):
        return None, None

    # wildcard rule
    if line.startswith("."):
        domain = f"*.{line[1:]}"                 # FQDN 值
        name_suffix = f"wildcard.{line[1:]}"     # 对象名称
        return domain, name_suffix

    # normal domain
    return line, line

# ================================
# Generate FortiOS config
# ================================
def generate_config(domains, names):
    output = []
    members = []
    member_bg_map = {}

    # Address objects
    for index, (domain, name_suffix) in enumerate(zip(domains, names)):
        bg_num = (index // CHUNK_SIZE) + 1
        obj_name = f"zzz_Domain_{bg_num}_{name_suffix}"

        members.append(obj_name)
        member_bg_map[obj_name] = bg_num

        output.append("config firewall address")
        output.append(f'    edit "{obj_name}"')
        output.append(f'        set type fqdn')
        output.append(f'        set fqdn "{domain}"')
        output.append(f'        set comment "update-date: {TODAY}"')
        output.append("    next")
        output.append("end\n")

    # BG groups
    bg_count = (len(domains) + CHUNK_SIZE - 1) // CHUNK_SIZE
    bg_list = []

    for g in range(1, bg_count + 1):
        bg_name = f"zzz_DomainBG_{g}"
        bg_list.append(bg_name)

        chunk_members = [m for m in members if member_bg_map[m] == g]

        output.append("config firewall addrgrp")
        output.append(f'    edit "{bg_name}"')
        output.append("        unset member")
        output.append("        set member " + " ".join(f'"{m}"' for m in chunk_members))
        output.append(f'        set comment "update-date: {TODAY}"')
        output.append("    next")
        output.append("end\n")

    # AG group
    output.append("config firewall addrgrp")
    output.append('    edit "zzz_DomainAG"')
    output.append("        unset member")
    output.append("        set member " + " ".join(f'"{bg}"' for bg in bg_list))
    output.append(f'        set comment "update-date: {TODAY}"')
    output.append("    next")
    output.append("end\n")

    return "\n".join(output)

# ================================
# Main
# ================================
def main():
    raw_lines = fetch_domains()
    domains = []
    names = []

    for line in raw_lines:
        domain, name_suffix = normalize_domain(line)
        if domain:
            domains.append(domain)
            names.append(name_suffix)

    print(f"Total domains: {len(domains)}")

    config = generate_config(domains, names)
    outfile = OUTPUT_DIR / "fortios_domain.conf.txt"
    outfile.write_text(config, encoding="utf-8")

    print(f"Generated: {outfile}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Generate taskfile entries for nuclei scan from categorized_templates directory.
Reads folder structure and generates nuclei commands with _partX suffix.
"""

import os
import re

COLLECTION_DIR = "{{.COLLECTION_DIR}}"
NUCLEI_OUT = "{{.NUCLEI_OUT}}"
CATEGORIZED_PATH = "categorized_templates"

# Severity mapping for specific categories
SEVERITY_MAP = {
    "cve": "-severity critical,high",
    "subdomain_takeover": "",
    "remote_code_execution": "",
    "sql_injection": "",
    "sql": "",
    "injection": "",
    "ldap": "",
    "crlf_injection": "",
    "xss": "",
    "ssrf": "",
    "local_file_inclusion": "",
    "open_redirect": "",
    "template_injection": "",
    "xml_external_entity": "",
    "apache": "",
    "nginx": "",
    "docker": "",
    "jenkins": "",
    "config": "",
    "debug": "",
    "panel": "",
    "exposed": "",
    "sensitive": "",
    "extract": "",
    "favicon": "",
    "default": "",
    "auth": "",
    "cross_site_request_forgery": "",
    "social": "",
    "api": "",
    "graphql": "",
    "http": "",
    "web": "",
    "fuzz": "",
    "search": "",
    "header": "",
    "other": "",
    "wordpress": "",
    "joomla": "",
    "drupal": "",
    "magento": "",
    "mysql": "",
    "postgres": "",
    "mongodb": "",
    "redis": "",
    "aws": "",
    "gcloud": "",
    "google": "",
    "java": "",
    "nodejs": "",
    "php": "",
    "python": "",
    "ruby": "",
    "airflow": "",
    "atlassian": "",
    "cisco": "",
    "coldfusion": "",
    "cpanel": "",
    "elk": "",
    "ibm": "",
    "kafka": "",
    "kong": "",
    "laravel": "",
    "netlify": "",
    "oracle": "",
    "rabbitmq": "",
    "sharepoint": "",
    "shopify": "",
    "smtp": "",
    "ssh": "",
    "vmware": "",
    "adobe": "",
    "backup": "",
    "detect": "",
    "directory_listing": "",
    "ftp": "",
    "git": "",
    "graphite": "",
    "javascript": "",
    "microsoft": "",
    "perl": "",
    "samba": "",
    "sap": "",
    "upload": "",
}

# Rate limits per category
RATE_LIMITS = {
    "cve": ("-bs 15 -c 25", "cat_cve"),
    "subdomain_takeover": ("-bs 20 -c 30", "cat_takeover"),
    "remote_code_execution": ("-bs 10 -c 15", "cat_rce"),
    "sql_injection": ("-bs 10 -c 15", "cat_sql_injection"),
    "sql": ("-bs 10 -c 15", "cat_sql"),
    "injection": ("-bs 10 -c 15", "cat_injection"),
    "ldap": ("-bs 10 -c 15", "cat_ldap"),
    "crlf_injection": ("-bs 10 -c 15", "cat_crlf"),
    "xss": ("-bs 8 -c 12", "cat_xss"),
    "ssrf": ("-bs 10 -c 15", "cat_ssrf"),
    "local_file_inclusion": ("-bs 10 -c 15", "cat_lfi"),
    "open_redirect": ("-bs 10 -c 15", "cat_open_redirect"),
    "template_injection": ("-bs 10 -c 15", "cat_template_injection"),
    "xml_external_entity": ("-bs 10 -c 15", "cat_xxe"),
    "apache": ("-bs 15 -c 20", "cat_apache"),
    "nginx": ("-bs 15 -c 20", "cat_nginx"),
    "docker": ("-bs 10 -c 15", "cat_docker"),
    "jenkins": ("-bs 10 -c 15", "cat_jenkins"),
    "config": ("-bs 10 -c 15", "cat_config"),
    "debug": ("-bs 10 -c 15", "cat_debug"),
    "panel": ("-bs 15 -c 20", "cat_panel"),
    "exposed": ("-bs 12 -c 18", "cat_exposed"),
    "sensitive": ("-bs 12 -c 18", "cat_sensitive"),
    "extract": ("-bs 10 -c 15", "cat_extract"),
    "favicon": ("-bs 10 -c 15", "cat_favicon"),
    "default": ("-bs 15 -c 20", "cat_default"),
    "auth": ("-bs 12 -c 18", "cat_auth"),
    "cross_site_request_forgery": ("-bs 10 -c 15", "cat_csrf"),
    "social": ("-bs 10 -c 15", "cat_social"),
    "api": ("-bs 10 -c 15", "cat_api"),
    "graphql": ("-bs 10 -c 15", "cat_graphql"),
    "http": ("-bs 8 -c 12", "cat_http"),
    "web": ("-bs 8 -c 10", "cat_web"),
    "fuzz": ("-bs 5 -c 8", "cat_fuzz"),
    "search": ("-bs 10 -c 15", "cat_search"),
    "header": ("-bs 10 -c 15", "cat_header"),
    "other": ("-bs 8 -c 12", "cat_other"),
    "wordpress": ("-bs 10 -c 15", "cat_wordpress"),
    "joomla": ("-bs 10 -c 15", "cat_joomla"),
    "drupal": ("-bs 10 -c 15", "cat_drupal"),
    "magento": ("-bs 10 -c 15", "cat_magento"),
    "mysql": ("-bs 10 -c 15", "cat_mysql"),
    "postgres": ("-bs 10 -c 15", "cat_postgres"),
    "mongodb": ("-bs 10 -c 15", "cat_mongodb"),
    "redis": ("-bs 10 -c 15", "cat_redis"),
    "aws": ("-bs 10 -c 15", "cat_aws"),
    "gcloud": ("-bs 10 -c 15", "cat_gcloud"),
    "google": ("-bs 10 -c 15", "cat_google"),
    "java": ("-bs 8 -c 12", "cat_java"),
    "nodejs": ("-bs 8 -c 12", "cat_nodejs"),
    "php": ("-bs 8 -c 12", "cat_php"),
    "python": ("-bs 8 -c 12", "cat_python"),
    "ruby": ("-bs 8 -c 12", "cat_ruby"),
    "airflow": ("-bs 10 -c 15", "cat_airflow"),
    "atlassian": ("-bs 10 -c 15", "cat_atlassian"),
    "cisco": ("-bs 10 -c 15", "cat_cisco"),
    "coldfusion": ("-bs 10 -c 15", "cat_coldfusion"),
    "cpanel": ("-bs 10 -c 15", "cat_cpanel"),
    "elk": ("-bs 10 -c 15", "cat_elk"),
    "ibm": ("-bs 10 -c 15", "cat_ibm"),
    "kafka": ("-bs 10 -c 15", "cat_kafka"),
    "kong": ("-bs 10 -c 15", "cat_kong"),
    "laravel": ("-bs 10 -c 15", "cat_laravel"),
    "netlify": ("-bs 10 -c 15", "cat_netlify"),
    "oracle": ("-bs 10 -c 15", "cat_oracle"),
    "rabbitmq": ("-bs 10 -c 15", "cat_rabbitmq"),
    "sharepoint": ("-bs 10 -c 15", "cat_sharepoint"),
    "shopify": ("-bs 10 -c 15", "cat_shopify"),
    "smtp": ("-bs 10 -c 15", "cat_smtp"),
    "ssh": ("-bs 10 -c 15", "cat_ssh"),
    "vmware": ("-bs 10 -c 15", "cat_vmware"),
    "adobe": ("-bs 8 -c 12", "cat_adobe"),
    "backup": ("-bs 8 -c 12", "cat_backup"),
    "detect": ("-bs 10 -c 15", "cat_detect"),
    "directory_listing": ("-bs 10 -c 15", "cat_directory_listing"),
    "ftp": ("-bs 10 -c 15", "cat_ftp"),
    "git": ("-bs 10 -c 15", "cat_git"),
    "graphite": ("-bs 10 -c 15", "cat_graphite"),
    "javascript": ("-bs 8 -c 12", "cat_javascript"),
    "microsoft": ("-bs 10 -c 15", "cat_microsoft"),
    "perl": ("-bs 8 -c 12", "cat_perl"),
    "samba": ("-bs 10 -c 15", "cat_samba"),
    "sap": ("-bs 10 -c 15", "cat_sap"),
    "upload": ("-bs 10 -c 15", "cat_upload"),
}


def get_categories_and_parts(path):
    """Scan categorized_templates directory and return sorted list of (category, parts)."""
    categories = {}
    pattern = re.compile(r'^(.+)_part(\d+)$')

    if not os.path.exists(path):
        print(f"Warning: Directory '{path}' does not exist!")
        return categories

    for folder in os.listdir(path):
        full_path = os.path.join(path, folder)
        if not os.path.isdir(full_path):
            continue

        match = pattern.match(folder)
        if match:
            cat_name = match.group(1)
            part_num = int(match.group(2))
        else:
            # Should not happen with new naming convention
            cat_name = folder
            part_num = 1

        if cat_name not in categories:
            categories[cat_name] = []
        categories[cat_name].append(part_num)

    # Sort parts for each category
    for cat in categories:
        categories[cat] = sorted(categories[cat])

    return categories


def generate_taskfile(categories, output_file=None):
    """Generate taskfile entries."""
    lines = []
    lines.append("# ==================== CATEGORIZED TEMPLATES (Auto-generated) ====================")
    lines.append("")

    # Group categories for organized output
    critical = ["cve", "subdomain_takeover", "remote_code_execution"]
    injection = ["sql_injection", "sql", "injection", "ldap", "crlf_injection"]
    web_vulns = ["xss", "ssrf", "local_file_inclusion", "open_redirect", "template_injection", "xml_external_entity"]
    infra = ["apache", "nginx", "docker", "jenkins", "config", "debug"]
    panels = ["panel", "exposed", "sensitive", "extract", "favicon"]
    auth_cat = ["default", "auth", "cross_site_request_forgery", "social"]
    api_services = ["api", "graphql", "http", "web", "fuzz", "search", "header", "other"]
    cms = ["wordpress", "joomla", "drupal", "magento"]
    databases = ["mysql", "postgres", "mongodb", "redis"]
    cloud = ["aws", "gcloud", "google"]
    languages = ["java", "nodejs", "php", "python", "ruby"]
    vendors = ["airflow", "atlassian", "cisco", "coldfusion", "cpanel", "elk", "ibm", "kafka", "kong",
               "laravel", "netlify", "oracle", "rabbitmq", "sharepoint", "shopify", "smtp", "ssh", "vmware"]
    others = ["adobe", "backup", "detect", "directory_listing", "ftp", "git", "graphite",
              "javascript", "microsoft", "perl", "samba", "sap", "upload"]

    groups = [
        ("CRITICAL", critical),
        ("HIGH PRIORITY - INJECTION", injection),
        ("HIGH PRIORITY - WEB VULNS", web_vulns),
        ("MEDIUM PRIORITY - INFRASTRUCTURE", infra),
        ("MEDIUM PRIORITY - PANELS & EXPOSURE", panels),
        ("MEDIUM PRIORITY - AUTH", auth_cat),
        ("API & SERVICES", api_services),
        ("CMS", cms),
        ("DATABASES", databases),
        ("CLOUD", cloud),
        ("LANGUAGES", languages),
        ("VENDORS & SERVICES", vendors),
        ("OTHERS", others),
    ]

    for group_name, group_cats in groups:
        cats_in_group = [c for c in group_cats if c in categories]
        if not cats_in_group:
            continue

        lines.append(f"      # --- {group_name} ---")
        for cat in cats_in_group:
            severity = SEVERITY_MAP.get(cat, "")
            for part in categories[cat]:
                folder = f"{cat}_part{part}"
                out_name = RATE_LIMITS.get(cat, ("", f"cat_{cat}"))[1]
                rate_limit = RATE_LIMITS.get(cat, ("-bs 10 -c 15", f"cat_{cat}"))[0]
                out_file = f"{NUCLEI_OUT}/{out_name}.txt"

                cmd = f"      - nuclei -t {COLLECTION_DIR}/{folder} -l {{.LIVE_HOSTS}} {severity} -o {out_file} {rate_limit}"
                lines.append(cmd)
        lines.append("")

    output = "\n".join(lines)
    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        print(f"Taskfile written to: {output_file}")
    else:
        print(output)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate nuclei taskfile from categorized_templates")
    parser.add_argument("-i", "--input", default=CATEGORIZED_PATH, help="Input directory (default: categorized_templates)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    args = parser.parse_args()

    categories = get_categories_and_parts(args.input)

    print(f"Found {len(categories)} categories:")
    for cat, parts in sorted(categories.items()):
        total_files = 0
        for part in parts:
            folder = f"{cat}_part{part}"
            folder_path = os.path.join(args.input, folder)
            if os.path.exists(folder_path):
                total_files += len([f for f in os.listdir(folder_path) if f.endswith(('.yml', '.yaml'))])
        if len(parts) > 1:
            print(f"  {cat}: {parts} ({total_files} files)")
        else:
            print(f"  {cat}: {total_files} files")
    print()

    generate_taskfile(categories, args.output)
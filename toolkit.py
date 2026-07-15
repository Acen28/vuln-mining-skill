"""
toolkit.py — Reusable utilities for vulnerability mining.

Usage:
    from toolkit import scan_sinks, port_scan, ssrf_test, ...
"""

import os, struct, socket, re, hashlib, subprocess
from pathlib import Path

# ══════════════════════════════════════════════════════════
# ELF Analysis
# ══════════════════════════════════════════════════════════

def elf_info(path):
    """Return {arch, bits, endian} for an ELF binary."""
    with open(path, 'rb') as f:
        data = f.read(20)
    if data[:4] != b'\x7fELF':
        return None
    bits = 64 if data[4] == 2 else 32
    endian = 'LE' if data[5] == 1 else 'BE'
    machine = struct.unpack('<H' if endian == 'LE' else '>H', data[18:20])[0]
    machines = {3:'x86', 40:'ARM', 0x28:'AArch64', 8:'MIPS', 0x3E:'x86-64', 0x14:'PowerPC'}
    return {'bits': bits, 'endian': endian, 'arch': machines.get(machine, f'0x{machine:x}')}

def find_sinks(binary_path):
    """Find all dangerous function PLT entries in an ELF binary."""
    sinks = ['system', 'popen', 'strcpy', 'sprintf', 'sscanf', 'strncpy',
             'execve', 'execl', 'wordexp', 'recv', 'recvfrom', 'gets']
    try:
        output = subprocess.run(
            ['objdump', '-T', binary_path],
            capture_output=True, text=True, timeout=10
        ).stdout
    except:
        return {}
    found = {}
    for sink in sinks:
        for line in output.split('\n'):
            if sink in line and ('GLIBC' in line or 'musl' in line.lower() or 'F *UND*' in line):
                found[sink] = line.strip().split()[0]
    return found

# ══════════════════════════════════════════════════════════
# Port Scanning
# ══════════════════════════════════════════════════════════

def port_scan(host, ports=None, timeout=1):
    """TCP port scan. Returns list of open ports."""
    if ports is None:
        ports = [21,22,23,53,80,443,139,445,1080,1883,1900,3306,3389,5000,
                 5353,5432,6379,7000,8000,8080,8443,8883,8888,9000,9001,
                 9090,9200,27017]
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((host, p))
            open_ports.append(p)
            s.close()
        except:
            pass
    return open_ports

# ══════════════════════════════════════════════════════════
# Web API Fuzzing
# ══════════════════════════════════════════════════════════

def api_fuzz(base_url, endpoints, token=None, method='GET', data=None):
    """
    Fuzz API endpoints. Returns {endpoint: response}.
    
    endpoints: list of URL paths
    token: if provided, inserted as stok=TOKEN in URL
    """
    import requests
    results = {}
    session = requests.Session()
    if token:
        base_url = base_url.replace('/api', f'/;stok={token}/api')
    for ep in endpoints:
        url = f"{base_url}{ep}"
        try:
            if method == 'POST':
                r = session.post(url, data=data or {}, timeout=3)
            else:
                r = session.get(url, timeout=3)
            if r.status_code == 200 and r.text and 'No page is registered' not in r.text:
                results[ep] = r.text[:200]
        except:
            pass
    return results

def generate_endpoints(controller_names, api_prefixes):
    """
    Generate URL patterns from controller filenames.
    
    controller_names: ['firewall', 'mipctl', 'url_fw', ...]
    api_prefixes: ['/api/xqsystem/', '/api/misystem/', ...]
    """
    endpoints = []
    for prefix in api_prefixes:
        for name in controller_names:
            endpoints.append(f"{prefix}{name}")
            endpoints.append(f"{prefix}{name}_list")
            endpoints.append(f"{prefix}{name}_info")
            endpoints.append(f"{prefix}set_{name}")
            endpoints.append(f"{prefix}{name}/status")
    return endpoints

# ══════════════════════════════════════════════════════════
# SSRF Testing
# ══════════════════════════════════════════════════════════

SSRF_PAYLOADS = [
    ('127.0.0.1', 80),
    ('127.0.0.1', 54322),
    ('[::1]', 54322),
    ('v4.localtest.me', 54322),   # IPv4-only DNS rebinding
    ('127.0.0.1.nip.io', 54322),
]

def ssrf_test(target, port, payload=None, timeout=5):
    """
    Test Host header SSRF.
    Returns (status_code, response_preview).
    """
    if payload is None:
        payload = b'{"method":"_internal.info"}'
    results = []
    for host, backend_port in SSRF_PAYLOADS:
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((target, port))
            req = (f"POST / HTTP/1.0\r\nHost: {host}:{backend_port}\r\n"
                   f"Content-Length: {len(payload)}\r\n\r\n").encode() + payload
            s.send(req)
            resp = s.recv(4096)
            s.close()
            code = resp.split(b' ')[1].decode() if resp else 'timeout'
            results.append((host, code, resp[:200]))
        except socket.timeout:
            results.append((host, 'timeout', b''))
        except Exception as e:
            results.append((host, str(e)[:50], b''))
    return results

# ══════════════════════════════════════════════════════════
# Hash Utilities
# ══════════════════════════════════════════════════════════

def file_hash(path, algo='sha256'):
    """Compute hash of a file."""
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def compare_binaries(path1, path2):
    """Compare two binary files by hash. Returns (same, hash1, hash2)."""
    h1 = file_hash(path1)
    h2 = file_hash(path2)
    return h1 == h2, h1, h2

# ══════════════════════════════════════════════════════════
# Script Audit
# ══════════════════════════════════════════════════════════

def audit_script(path):
    """Find dangerous patterns in a shell script."""
    dangerous = []
    patterns = [
        (r'\bsystem\b', 'system() call'),
        (r'\bpopen\b', 'popen() call'),
        (r'\beval\b', 'eval'),
        (r'\$\(', 'command substitution $()'),
        (r'`[^`]+`', 'backtick execution'),
        (r'\bexec\s+\S', 'exec command'),
    ]
    with open(path, 'r', errors='ignore') as f:
        lines = f.readlines()
    for i, line in enumerate(lines, 1):
        for pattern, desc in patterns:
            if re.search(pattern, line):
                dangerous.append((i, desc, line.strip()[:100]))
    return dangerous

# ══════════════════════════════════════════════════════════
# UCI/Config Helpers
# ══════════════════════════════════════════════════════════

def parse_uci_config(path):
    """Parse OpenWrt UCI config file into dict."""
    result = {}
    current_section = None
    current_type = None
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            if line.startswith('config '):
                parts = line.split()
                current_type = parts[1] if len(parts) > 1 else 'global'
                current_section = parts[2] if len(parts) > 2 else 'main'
                key = f"{current_type}.{current_section}"
                result[key] = {}
            elif line.startswith('option ') or line.startswith('list '):
                parts = line.split(None, 3)
                cmd, name = parts[0], parts[1]
                value = parts[2] if len(parts) > 2 else ''
                if current_section:
                    if cmd == 'list':
                        result.setdefault(key, {}).setdefault(name, []).append(value.strip("'"))
                    else:
                        result.setdefault(key, {})[name] = value.strip("'")
    return result

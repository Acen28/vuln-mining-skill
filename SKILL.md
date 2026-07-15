# Vulnerability Hunting Methodology

Universal sink-to-source vulnerability discovery. Applicable to any target — firmware, web apps, binaries, IoT, embedded Linux. Derived from real-world zero-day exploitation across multiple devices.

## Phase 1: Reconnaissance & Triage

**Goal:** Map attack surface, prioritize targets by exploit potential.

### 1.1 File System Mapping
- List all binaries by size — larger files = more code = more bugs.
- `find . -type f -executable | xargs ls -lhS | head -50`
- Tag each binary: network-facing / internal / utility.

### 1.2 Service Discovery
- `nmap -sT -p- <target>` — TCP full scan.
- Check localhost-only services: they need SSRF chains but have less hardening.
- Identify key services: web (80/443/8080), DNS (53), MQTT (1883/8883), UPnP (1900/5000), SSH (22), Telnet (23).

### 1.3 Credential & Config Quick Wins
- `/etc/shadow` — weak hashes, default accounts.
- nginx/apache configs — hidden endpoints, `proxy_pass`, `rewrite` rules.
- Hardcoded strings in binaries: `strings binary | grep -i 'key\|secret\|token\|password\|admin'`.
- .so plugins — often small authentication modules (easy to reverse).

### 1.4 Priority Ranking

| Priority | Rule |
|----------|------|
| **P0** | Network-facing, >50KB, handles external input |
| **P1** | Network-facing, any size, auth/proxy function |
| **P2** | Internal binary with `system()`/`popen()`/`wordexp()` |
| **P3** | Shell scripts, config files |

---

## Phase 2: Sink-to-Source Analysis

The fastest path from unknown binary to exploitable vulnerability.

### 2.1 Identify All Sinks

```
system()     → command injection (highest impact)
popen()      → command injection
exec*()      → command injection  
wordexp()    → shell expansion (= system())
sprintf()    → buffer overflow / format string
strcpy()     → buffer overflow
recv()       → network input entry point
sscanf()     → controlled parsing
```

For each: `find code_ref` in IDA or `objdump -d | grep '<system@'`.

### 2.2 Classify Each Sink

| Pattern | Exploitable? |
|---------|-------------|
| `system("hardcoded cmd")` | ❌ Skip |
| `system("cmd " + var)` | 🔥 TRACE NOW |
| `system("cmd \"$var\"")` + `setenv(var, val)` | 🔥 Quote escape injection |
| `sprintf(buf, fmt, arg)` where arg is user data | 🟡 Check bounds |
| `strcpy(dst, src)` where src is user data | 🟡 Check dst size |

### 2.3 Trace Dynamic Parameters Upstream

```
system("ipset -! del " + dynamic_var)
  → Find: where is dynamic_var assigned?
    → It comes from blobmsg_parse("device")
      → It comes from ubus handler "mipctl_devs_user"
        → It comes from ??? (Web API? Cloud? Local IPC?)
```

If the chain breaks at an unreachable IPC boundary → note it and move on.
If the chain reaches network/external input → **you have a vulnerability**.

### 2.4 Protocol Reverse Engineering

If the communication is encrypted:
1. Find the decrypt function (look for XOR loops, hex decode, OpenSSL calls).
2. Extract the key (global .data variable, hardcoded string, derived from device ID).
3. Reimplement in Python: `encrypt(msg) = hex_encode(xor_with_key(-15 + msg))`.
4. Test in QEMU first.

---

## Phase 3: Web API Discovery

### 3.1 Static Config Analysis
- Parse nginx `server { location ... }` blocks exhaustively.
- Find endpoints WITHOUT authentication (`return 301` for `$remote_addr != "127.0.0.1"` is the authenticator).
- Find `proxy_pass http://$http_host/` patterns → Host header SSRF.
- Find `fastcgi_pass 127.0.0.1:8920` — this is the backend CGI gateway.
- Find `internal;` directives — these can't be accessed directly but can be reached via `rewrite`.

### 3.2 Dynamic Endpoint Discovery
1. Open browser DevTools → Network tab.
2. Navigate through EVERY page in the web interface.
3. Save ALL XHR/fetch requests → this is the real API map.
4. For compiled controllers (Lua bytecode, Java .class): list filenames, derive URL patterns.

### 3.3 API Fuzzing Pipeline

```python
# Phase 1: Unauthenticated
for endpoint in endpoints:
    for method in [GET, POST]:
        send(method, endpoint, no_auth)

# Phase 2: Authenticated (if credentials known)
for endpoint in all_endpoints:
    for param in ['url', 'path', 'host', 'ip', 'target', 'cmd', 'data']:
        send(method, endpoint, auth, {param: payload})
```

### 3.4 SSRF Hunting

```
# Host header injection
curl -H "Host: 127.0.0.1:54322" http://target/
curl -H "Host: [::1]:54322" http://target/
curl -H "Host: v4.localtest.me:54322" http://target/  # IPv4-only DNS rebinding
curl -H "Host: 127.0.0.1.nip.io:54322" http://target/

# Response codes:
# 502 = proxy_pass triggered, backend unreachable
# Timeout = TCP connected, backend not responding with HTTP
# 200 = normal page (SSRF not triggered)
```

### 3.5 Endpoint Name Guessing

```python
# From controller filenames, generate URL variants
names = ['firewall', 'fw', 'security', 'mipctl', 'parent_control']
prefixes = ['/api/misystem/', '/api/xqsystem/', '/api/xqnetwork/', 
            '/cgi-bin/luci/', '/cgi-bin/luci/;stok=TOKEN/']
# Brute-force ALL combinations
```

---

## Phase 4: IPC & Cross-Daemon Mapping

### 4.1 Identify IPC Mechanisms
- `ubus` — OpenWrt IPC, Unix socket `/var/run/ubus.sock`.
- Unix domain sockets — `find /tmp /var/run -type s`.
- MQTT — broker on 1883/8883, topic-based pub/sub.
- Shared memory / message queues — `/dev/mqueue/`.

### 4.2 Build the Service Graph

```
Web API → nginx → fastcgi (127.0.0.1:8920) → LuCI → ubus → backend_daemon → system()
LAN → MQTT (8883) → thrifttunnel → ubus → backend_daemon → system()
```

Find the "bridge" services that connect external → internal. These are gold.

### 4.3 Auth Plugin Analysis
- Small .so files in `/usr/lib/` with `auth` in name.
- < 20KB → can fully reverse in < 30 minutes.
- Look for: credential comparison, hardcoded keys, fallback logic.

---

## Phase 5: Shell Script & Config Injection

### 5.1 Quick Scan
```bash
grep -r 'system\|popen\|exec \|eval \|\$(' --include='*.sh' .
grep -r '``' --include='*.sh' .
```

### 5.2 Trace Variables to Inputs
For each dynamic variable in a system() call:
- Does it come from UCI? → Can UCI be written via Web API?
- Does it come from a network callback? → Can we trigger the callback?
- Does it come from a config file? → Can the file be uploaded?

### 5.3 Callback Execution Chains
```
miio_resp.sh: find "$UNBOUND_CB" -type f -exec sh -c 'sh $1 &' _ {} \;
```
- `$UNBOUND_CB = /etc/miio/unbound.d/`
- If we can write a file there → it gets executed → RCE.
- How to write? Firmware upload, backup restore, config import, path traversal.

---

## Phase 6: QEMU Emulation & PoC

### 6.1 User-Mode Emulation
```bash
# For ARM binaries
cp /usr/bin/qemu-arm-static <rootfs>/usr/bin/
chroot <rootfs> qemu-arm-static /bin/binary

# Or without chroot
qemu-arm -L <rootfs> ./usr/bin/target -d /data/dir -l 2
```

### 6.2 Fake Environment Setup
```bash
mkdir -p proc/xiaoqiang etc/config dev/mqueue tmp var/run
echo "model_name" > proc/xiaoqiang/model
echo "fw_version" > etc/device_info
# Add required UCI configs
# Create empty directories for writable paths
```

### 6.3 Debugging Startup Failures
```bash
# strace shows exactly which files/paths are missing
qemu-arm -strace ./binary 2>&1 | head -100
```

### 6.4 PoC Quality Requirements for SRC
- Code path verified (IDA decompilation + address).
- QEMU emulation log showing code path hit.
- Real device verification (when possible).
- **Code analysis + emulation alone is often sufficient for IoT SRC submission.**

---

## Phase 7: Reporting

### Report Template
```
[Title] Product Model: Vulnerability Type

[Device]
Model: Xiaomi Router BE3600 (RD15)
Firmware: 1.0.87

[Description]
One-paragraph summary of what the vulnerability is and how it works.

[Code Analysis]
Function sub_XXXX at 0xXXXX:
```c
// decompiled code showing the vulnerable path
```

[Proof of Concept]
- QEMU emulation log
- Python PoC script
- Real device verification (optional but preferred)

[Impact]
What can an attacker do? (RCE, DoS, info leak)

[Fix]
Suggested remediation.
```

### Evidence Strength
| Level | Acceptable for SRC? |
|-------|-------------------|
| Code audit only (IDA) | ❌ Usually not |
| Code + QEMU emulation | ✅ IoT/embedded devices |
| Code + real device | ✅ Best |
| Real device only | ✅ Web/mobile |

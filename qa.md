# Common Failure Modes & Fixes

Quick reference for when you're stuck.

## Binary Crashes in QEMU

```
Error: path is NULL (arch_file_path_check)
Fix: Add -d <data_dir> parameter. Check init script for default args.

Error: Data dir path check failed
Fix: Create the directory specified in the init script (/data/miio_ot/, /etc/miio/, etc.)

Error: missing lib* or ld-*
Fix: Verify all .so files present in rootfs/lib/. Copy qemu-arm-static to rootfs/usr/bin/.
```

## Web API Returns 404 for Everything

```
- Check if your token expired (stok changes on reboot)
- Endpoints may use different URL format: /cgi-bin/luci/<name> not /api/<name>
- Compiled Lua bytecode hides routes — use browser DevTools Network tab instead
- Token must be in URL path: /cgi-bin/luci/;stok=TOKEN/api/...
```

## SSRF Timeout vs 502

```
502 Bad Gateway = DNS resolved, proxy connected, backend sent bad/no response
Timeout = DNS resolving or TCP connecting (may have connected but backend hung)
- 502 from public IP = proxy PASS is working
- Timeout from localhost = DNS resolved to ::1 (IPv6) instead of 127.0.0.1
- Fix: use v4.localtest.me (IPv4-only DNS rebinding)
```

## Command Injection Not Triggering

```
system() returned "success" but no execution:
- Input may be stored in UCI/config but not immediately applied
- May need to trigger a "reload" or "restart" to apply the value
- Check if the value goes through `setenv()` — quote escape may be needed
- The binary may use a different code path than expected (check callers)
```

## MQTT / IPC Not Reachable

```
- IPC is on Unix sockets → need local access or SSRF to ubus relay
- MQTT requires TLS + auth → check auth plugin
- Auth plugin is small (< 20KB) → fully reverse it
- Default credentials may work
- If device is standalone (not meshed), IPC may be disabled
```

## Sink-to-Source Chain Breaks

```
If all sinks with dynamic content trace back to IPC that's unreachable:
1. Check if any network-facing binary calls that IPC
2. Look for "bridge" services (thrift, proxy, relay, tunnel in binary names)
3. Check if MQTT or cloud API exposes the IPC behind authentication
4. Sometimes the vulnerability exists but needs a second vulnerability to trigger
```

## Getting Unstuck

```
Stuck on one binary for > 2 hours → move to next.
Stuck on API fuzzing → use browser DevTools instead.
Stuck on protocol → find the decrypt function in IDA.
Stuck on auth → reverse the auth plugin (usually tiny).
Stuck on everything → start over with a fresh port scan, look for missed services.
```

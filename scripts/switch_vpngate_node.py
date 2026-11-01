"""切换 sing-box 到 /tmp/verified_nodes.json 中的下一个已验证 200 节点。"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

STATE_FILE = "/tmp/vpngate_current_idx.txt"
VERIFIED_FILE = "/tmp/verified_nodes.json"
SB_CFG = "/tmp/sb.json"

if not os.path.exists(VERIFIED_FILE):
    print("[VPNGate Switch] /tmp/verified_nodes.json 不存在，跳过切换", flush=True)
    sys.exit(0)

try:
    nodes = json.loads(Path(VERIFIED_FILE).read_text(encoding="utf-8"))
except Exception as e:
    print(f"[VPNGate Switch] 解析 verified_nodes 失败: {e}", flush=True)
    sys.exit(0)

if not nodes:
    print("[VPNGate Switch] 没有可用的验证节点", flush=True)
    sys.exit(0)

current = 0
if os.path.exists(STATE_FILE):
    try:
        current = int(Path(STATE_FILE).read_text().strip())
    except Exception:
        current = 0

next_idx = (current + 1) % len(nodes)
Path(STATE_FILE).write_text(str(next_idx))

chosen_node = nodes[next_idx]
srv = chosen_node["server"]
port = chosen_node["server_port"]
country = chosen_node.get("country_short", "")
print(f"[VPNGate Switch] 切换到节点 #{next_idx}: {srv}:{port} ({country})", flush=True)

ep = dict(chosen_node["endpoint"])
ep["tag"] = "vpngate-active"
config = {
    "log": {"level": "info"},
    "endpoints": [ep],
    "outbounds": [{"type": "direct", "tag": "direct"}],
    "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 18080}],
    "route": {"final": "vpngate-active"},
}
Path(SB_CFG).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

# 重启 sing-box
subprocess.run(["pkill", "-f", "sing-box.*sb.json"], check=False)
time.sleep(1)
subprocess.Popen(["sing-box", "run", "-c", SB_CFG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
print(f"[VPNGate Switch] sing-box 已切换到节点 #{next_idx} ({srv}) 并重启完毕", flush=True)

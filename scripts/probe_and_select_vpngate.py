"""20 并发全量探节点死活 + 20 并发通过 sing-box 端口连接 zen-direct 真实发消息探测 200。"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import vpngate_to_singbox as v2s


def wait_port(port: int, proc: subprocess.Popen, deadline: float) -> bool:
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.4):
                return True
        except OSError:
            if proc.poll() is not None:
                return False
            time.sleep(0.2)
    return False


def test_candidate_node(
    idx: int,
    cand: tuple[int, str, str, dict],
    zen_bin: str,
    singbox_bin: str = "sing-box",
) -> dict | None:
    speed, country, country_short, ep = cand
    host, srv_port = v2s.primary_server(ep)
    sb_port = 19100 + idx
    gw_port = 19200 + idx
    tag = f"vpn-test-{idx}"
    ep_copy = dict(ep)
    ep_copy["tag"] = tag

    cfg_data = {
        "log": {"level": "warn"},
        "endpoints": [ep_copy],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": sb_port}],
        "route": {"final": tag},
    }

    cfg_file = f"/tmp/sb_cand_{idx}.json"
    log_file = f"/tmp/sb_cand_{idx}.log"
    Path(cfg_file).write_text(json.dumps(cfg_data), encoding="utf-8")
    log_h = open(log_file, "wb")
    sb_proc = subprocess.Popen([singbox_bin, "run", "-c", cfg_file],
                               stdout=subprocess.DEVNULL, stderr=log_h)
    start_t = time.time()
    try:
        if not wait_port(sb_port, sb_proc, time.time() + 15):
            return None

        # 轮询等待隧道建立（通过该端口能出网，最多 20 秒）
        tunnel_ok = False
        deadline = time.time() + 20
        while time.time() < deadline:
            if sb_proc.poll() is not None:
                break
            try:
                r = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "4",
                     "-x", f"http://127.0.0.1:{sb_port}", "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=5,
                )
                if (r.stdout or "").strip() == "200":
                    tunnel_ok = True
                    break
            except Exception:
                pass
            time.sleep(1.2)

        if not tunnel_ok:
            print(f"[TUNNEL_FAIL] 节点 #{idx:02d} {host}:{srv_port} 隧道未能在 20s 内出网", flush=True)
            return None

        # 隧道已通！启动一个配套的临时 zen-direct 网关，通过该 sing-box 端口代理出网
        gw_env = dict(
            os.environ,
            PORT=str(gw_port),
            HTTPS_PROXY=f"http://127.0.0.1:{sb_port}",
            HTTP_PROXY=f"http://127.0.0.1:{sb_port}",
            ALL_PROXY=f"http://127.0.0.1:{sb_port}",
            NO_PROXY="127.0.0.1,localhost",
            ZEN_TLS="bun",
            DIRECT_SIDECAR="off",
            DIRECT_CONCURRENCY="4",
        )
        gw_log = open(f"/tmp/gw_cand_{idx}.log", "wb")
        gw_proc = subprocess.Popen([zen_bin], env=gw_env, stdout=subprocess.DEVNULL, stderr=gw_log)

        try:
            if not wait_port(gw_port, gw_proc, time.time() + 8):
                return None

            # 发送原模板完全相同的 PROBE_PAYLOAD 发起真实 chat completion 探活
            probe_payload = json.dumps({
                "model": "deepseek-v4.1-flash-free",
                "messages": [
                    {"role": "system", "content": "You are opencode, a coding agent. Answer concisely."},
                    {"role": "user", "content": "用一句话说明你能做什么。"},
                    {"role": "assistant", "content": "我可以帮你读写代码、运行命令、排查问题。"},
                    {"role": "user", "content": "好，只回复：ok"}
                ],
                "max_tokens": 128,
                "stream": True
            })

            res = subprocess.run(
                [
                    "curl", "-sS", "-o", f"/tmp/probe_{idx}.json", "-w", "%{http_code}",
                    "-m", "25",
                    "-H", "Content-Type: application/json",
                    "-H", "Authorization: Bearer public",
                    "-H", "User-Agent: zen-probe",
                    "--data-binary", probe_payload,
                    f"http://127.0.0.1:{gw_port}/v1/chat/completions"
                ],
                capture_output=True, text=True, timeout=30
            )
            code = (res.stdout or "").strip()
            elapsed_ms = int((time.time() - start_t) * 1000)

            if code == "200":
                print(f"[VERIFIED 200] 节点 #{idx:02d} {host}:{srv_port} ({country_short}) 真实发包 200 验证通过: {elapsed_ms}ms", flush=True)
                return {
                    "endpoint": ep_copy,
                    "server": host,
                    "server_port": srv_port,
                    "country": country,
                    "country_short": country_short,
                    "latency_ms": elapsed_ms,
                }
            else:
                body_sample = ""
                try:
                    body_sample = Path(f"/tmp/probe_{idx}.json").read_text(encoding="utf-8", errors="replace")[:120].replace("\n", " ")
                except Exception:
                    pass
                print(f"[REJECTED] 节点 #{idx:02d} {host}:{srv_port} 真实发包未过 200 (HTTP {code}): {body_sample}", flush=True)
                return None
        finally:
            gw_proc.terminate()
            try:
                gw_proc.wait(2)
            except subprocess.TimeoutExpired:
                gw_proc.kill()
            gw_log.close()
            for f in [f"/tmp/gw_cand_{idx}.log", f"/tmp/probe_{idx}.json"]:
                try:
                    os.remove(f)
                except OSError:
                    pass
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] 节点 #{idx:02d} {host}:{srv_port} 异常: {exc}", flush=True)
        return None
    finally:
        sb_proc.terminate()
        try:
            sb_proc.wait(3)
        except subprocess.TimeoutExpired:
            sb_proc.kill()
        log_h.close()
        for f in [cfg_file, log_file]:
            try:
                os.remove(f)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="20 并发探死活 + 20 并发连接 zen-direct 真实发包探测 200")
    parser.add_argument("--csv", required=True, help="VPNGate snapshot CSV file")
    parser.add_argument("--output", default="/tmp/sb.json", help="Output sing-box config path")
    parser.add_argument("--zen-bin", default="bin/zen-direct", help="Path to zen-direct binary")
    parser.add_argument("--singbox-bin", default="sing-box", help="Path to sing-box binary")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrency for probes (default 20)")
    parser.add_argument("--max-candidates", type=int, default=25, help="Max candidates for phase 2 (default 25)")
    parser.add_argument("--keep-nodes", type=int, default=3, help="Number of verified 200 nodes to keep in config (default 3)")
    parser.add_argument("--mixed-port", type=int, default=18080, help="Production mixed inbound port (default 18080)")
    args = parser.parse_args()

    csv_text = Path(args.csv).read_text(encoding="utf-8")
    candidates = list(v2s._iter_tcp_candidates(csv_text))
    if not candidates:
        print("[VPNGate] CSV 中没有找到合法的 TCP OpenVPN 节点！", file=sys.stderr)
        return 1

    # ==========================================
    # 阶段一：20 并发全量探节点死活（TCP 握手探活）
    # ==========================================
    print(f"\n[阶段一] 启动 {args.concurrency} 并发全量探节点死活（共 {len(candidates)} 个候选节点）...", flush=True)
    t0 = time.time()
    alive_candidates: list[tuple[int, int, str, str, dict]] = []

    def check_alive(cand):
        speed, country, country_short, ep = cand
        host, srv_port = v2s.primary_server(ep)
        lat = v2s.probe_tcp_latency(host, srv_port, timeout=2.5)
        return (lat, speed, country, country_short, ep) if lat > 0 else None

    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(check_alive, cand): cand for cand in candidates}
        for fut in cf.as_completed(futures):
            res = fut.result()
            if res is not None:
                alive_candidates.append(res)

    alive_candidates.sort(key=lambda x: x[0])  # 按 TCP 握手延迟升序排序
    elapsed_p1 = int((time.time() - t0) * 1000)
    print(f"[阶段一完成] 耗时 {elapsed_p1}ms：在 {len(candidates)} 个节点中发现 {len(alive_candidates)} 个存活节点！", flush=True)

    if not alive_candidates:
        print("[VPNGate] 错误：没有找到任何存活节点！", file=sys.stderr)
        return 1

    # =========================================================================
    # 阶段二：20 并发对每个存活节点通过 sing-box 连接 zen-direct 真实发包探测 200
    # =========================================================================
    test_pool = alive_candidates[: args.max_candidates]
    print(f"\n[阶段二] 启动 {args.concurrency} 并发通过 sing-box 连接 zen-direct 真实发消息探测 200（测试前 {len(test_pool)} 个存活节点）...", flush=True)
    verified_nodes: list[dict] = []
    t1 = time.time()

    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(
                test_candidate_node,
                i,
                (cand[1], cand[2], cand[3], cand[4]),
                args.zen_bin,
                args.singbox_bin,
            ): cand
            for i, cand in enumerate(test_pool)
        }
        for fut in cf.as_completed(futures):
            res = fut.result()
            if res is not None:
                verified_nodes.append(res)

    verified_nodes.sort(key=lambda x: x["latency_ms"])
    elapsed_p2 = int((time.time() - t1) * 1000)
    print(f"\n[阶段二完成] 耗时 {elapsed_p2}ms：共筛选出 {len(verified_nodes)} 个真实发包成功返回 HTTP 200 的纯净可用节点！", flush=True)

    # ==========================================
    # 阶段三：生成最终出口配置
    # ==========================================
    if verified_nodes:
        # 保存所有通过 200 验证的节点列表，供后续遭遇 429 时热切换自愈
        Path("/tmp/verified_nodes.json").write_text(
            json.dumps(verified_nodes, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        Path("/tmp/vpngate_current_idx.txt").write_text("0")

        chosen = verified_nodes[: args.keep_nodes]
        print(f"[VPNGate] 选用排名前 {len(chosen)} 的 200 节点组建最终代理池（共保存 {len(verified_nodes)} 个备选）：", flush=True)
        final_endpoints = []
        for i, node in enumerate(chosen):
            ep = dict(node["endpoint"])
            ep["tag"] = f"vpngate-{i}"
            final_endpoints.append(ep)
            print(f"  -> 节点 #{i}: {node['server']}:{node['server_port']} ({node['country_short']}), 真实探测延迟={node['latency_ms']}ms", flush=True)

        config = v2s.build_singbox_config(
            final_endpoints,
            mixed_listen="127.0.0.1",
            mixed_port=args.mixed_port,
        )
        Path(args.output).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        print(f"[VPNGate] 已写入最终 sing-box 配置文件: {args.output} (监听 127.0.0.1:{args.mixed_port})", flush=True)
        return 0
    else:
        print("[VPNGate] 警告: 没有节点在本次真实探测中拿到 200！将采用最快的前 3 个备用节点启动 sing-box...", file=sys.stderr)
        fallback_endpoints = []
        for i, cand in enumerate(alive_candidates[:3]):
            ep = dict(cand[4])
            ep["tag"] = f"vpngate-{i}"
            fallback_endpoints.append(ep)
        config = v2s.build_singbox_config(
            fallback_endpoints,
            mixed_listen="127.0.0.1",
            mixed_port=args.mixed_port,
        )
        Path(args.output).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        return 0


if __name__ == "__main__":
    sys.exit(main())

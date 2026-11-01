"""极致提速版：50 并发握手粗筛 + 35 并发秒级探测 200 + 极速早停机制。"""
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
import uuid
from pathlib import Path

import vpngate_to_singbox as v2s


def wait_port(port: int, proc: subprocess.Popen, deadline: float) -> bool:
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.15):
                return True
        except OSError:
            if proc.poll() is not None:
                return False
            time.sleep(0.08)
    return False


def test_candidate_node(
    idx: int,
    cand: tuple[int, str, str, dict],
    zen_bin: str,
    probe_body: str,
    singbox_bin: str = "sing-box",
) -> dict | None:
    speed, country, country_short, ep = cand
    host, srv_port = v2s.primary_server(ep)
    sb_port = 19100 + idx
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
        if not wait_port(sb_port, sb_proc, time.time() + 8):
            return None

        # 极速等待隧道建立（使用超轻量 HTTP 204 代替耗时 HTTPS，每 0.25s 探测一次）
        tunnel_ok = False
        deadline = time.time() + 10
        while time.time() < deadline:
            if sb_proc.poll() is not None:
                break
            try:
                r = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "1.2",
                     "-x", f"http://127.0.0.1:{sb_port}", "http://cp.cloudflare.com/generate_204"],
                    capture_output=True, text=True, timeout=1.8,
                )
                if (r.stdout or "").strip() in ("204", "200"):
                    tunnel_ok = True
                    break
            except Exception:
                pass
            time.sleep(0.25)

        if not tunnel_ok:
            return None

        # 隧道已通！直接调用 bin/zen-direct 纯探针模式（单次发包退出，仅需 400ms，无需启动网关端口）
        probe_ses = f"ses_{uuid.uuid4().hex[:20]}"
        probe_env = dict(
            os.environ,
            HTTPS_PROXY=f"http://127.0.0.1:{sb_port}",
            HTTP_PROXY=f"http://127.0.0.1:{sb_port}",
            ALL_PROXY=f"http://127.0.0.1:{sb_port}",
            NO_PROXY="127.0.0.1,localhost",
            ZEN_PROBE_BODY=probe_body,
            ZEN_PROBE_SESSION=probe_ses,
            ZEN_PROBE_UA="opencode/latest/2.2.5/cli",
            ZEN_TLS="bun",
        )
        res = subprocess.run([zen_bin], env=probe_env, capture_output=True, text=True, timeout=12)
        out = (res.stdout or "") + (res.stderr or "")
        elapsed_ms = int((time.time() - start_t) * 1000)

        if res.returncode == 0 or "-> 200" in out:
            print(f"[VERIFIED 200] 节点 #{idx:02d} {host}:{srv_port} ({country_short}) 探测成功: {elapsed_ms}ms", flush=True)
            return {
                "endpoint": ep_copy,
                "server": host,
                "server_port": srv_port,
                "country": country,
                "country_short": country_short,
                "latency_ms": elapsed_ms,
            }
        else:
            first_line = out.strip().split("\n")[0] if out.strip() else f"rc={res.returncode}"
            print(f"[REJECTED] 节点 #{idx:02d} {host}:{srv_port} 未过 200: {first_line[:90]}", flush=True)
            return None
    except Exception:
        return None
    finally:
        sb_proc.terminate()
        try:
            sb_proc.wait(1.5)
        except subprocess.TimeoutExpired:
            sb_proc.kill()
        log_h.close()
        for f in [cfg_file, log_file]:
            try:
                os.remove(f)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="极致并发探活与选择可用 200 节点")
    parser.add_argument("--csv", required=True, help="VPNGate snapshot CSV file")
    parser.add_argument("--output", default="/tmp/sb.json", help="Output sing-box config path")
    parser.add_argument("--zen-bin", default="bin/zen-direct", help="Path to zen-direct binary")
    parser.add_argument("--probe-body", default="scripts/probe_body.json", help="Path to probe_body.json")
    parser.add_argument("--singbox-bin", default="sing-box", help="Path to sing-box binary")
    parser.add_argument("--concurrency", type=int, default=35, help="Concurrency for probes (default 35)")
    parser.add_argument("--max-candidates", type=int, default=50, help="Max candidates for phase 2 (default 50)")
    parser.add_argument("--keep-nodes", type=int, default=3, help="Number of verified 200 nodes to keep (default 3)")
    parser.add_argument("--mixed-port", type=int, default=18080, help="Production mixed inbound port (default 18080)")
    args = parser.parse_args()

    csv_text = Path(args.csv).read_text(encoding="utf-8")
    candidates = list(v2s._iter_tcp_candidates(csv_text))
    if not candidates:
        print("[VPNGate] CSV 中没有找到合法的 TCP OpenVPN 节点！", file=sys.stderr)
        return 1

    # ==========================================
    # 阶段一：50 并发全量探节点死活（TCP 握手极速粗筛）
    # ==========================================
    print(f"\n[阶段一] 启动 50 并发全量探节点死活（共 {len(candidates)} 个候选节点）...", flush=True)
    t0 = time.time()
    alive_candidates: list[tuple[int, int, str, str, dict]] = []

    def check_alive(cand):
        speed, country, country_short, ep = cand
        host, srv_port = v2s.primary_server(ep)
        lat = v2s.probe_tcp_latency(host, srv_port, timeout=1.5)
        return (lat, speed, country, country_short, ep) if lat > 0 else None

    with cf.ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(check_alive, cand): cand for cand in candidates}
        for fut in cf.as_completed(futures):
            res = fut.result()
            if res is not None:
                alive_candidates.append(res)

    def rank_key(cand):
        ep = cand[4]
        host, _ = v2s.primary_server(ep)
        # 筑波大学公共总机房段（219.100.37.x 等）常年被数千人刷满 429
        # 将干净的独立住宅/商业志愿节点排在最前，公共滥用段放最后，极大提升 200 命中率！
        is_abused = host.startswith("219.100.37.") or host.startswith("150.40.105.")
        return (1 if is_abused else 0, cand[0])

    alive_candidates.sort(key=rank_key)
    elapsed_p1 = int((time.time() - t0) * 1000)
    print(f"[阶段一完成] 耗时 {elapsed_p1}ms：筛选出 {len(alive_candidates)} 个存活节点（已优先前置独立住宅出口）！", flush=True)

    if not alive_candidates:
        print("[VPNGate] 错误：没有找到任何存活节点！", file=sys.stderr)
        return 1

    # =========================================================================
    # 阶段二：35 并发通过 sing-box 连接 zen-direct 真实发包探测 200（极速早停）
    # =========================================================================
    test_pool = alive_candidates[: args.max_candidates]
    print(f"\n[阶段二] 启动 {args.concurrency} 并发真实发消息探测 200（早停阈值={args.keep_nodes} 个）...", flush=True)
    verified_nodes: list[dict] = []
    t1 = time.time()

    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(
                test_candidate_node,
                i,
                (cand[1], cand[2], cand[3], cand[4]),
                args.zen_bin,
                args.probe_body,
                args.singbox_bin,
            ): cand
            for i, cand in enumerate(test_pool)
        }
        for fut in cf.as_completed(futures):
            try:
                res = fut.result()
                if res is not None:
                    verified_nodes.append(res)
                    if len(verified_nodes) >= args.keep_nodes:
                        print(f"\n[极速早停] 已凑齐前 {len(verified_nodes)} 个实测 200 节点，立即收工！", flush=True)
                        for f in futures:
                            f.cancel()
                        break
            except Exception:
                pass

    verified_nodes.sort(key=lambda x: x["latency_ms"])
    elapsed_p2 = int((time.time() - t1) * 1000)
    print(f"\n[阶段二完成] 耗时 {elapsed_p2}ms：获得 {len(verified_nodes)} 个成功返回 HTTP 200 的纯净可用节点！", flush=True)

    # ==========================================
    # 阶段三：生成最终出口配置
    # ==========================================
    if verified_nodes:
        Path("/tmp/verified_nodes.json").write_text(
            json.dumps(verified_nodes, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        Path("/tmp/vpngate_current_idx.txt").write_text("0")

        chosen = verified_nodes[: args.keep_nodes]
        print(f"[VPNGate] 选用实测 200 节点组建最终代理池：", flush=True)
        final_endpoints = []
        for i, node in enumerate(chosen):
            ep = dict(node["endpoint"])
            ep["tag"] = f"vpngate-{i}"
            final_endpoints.append(ep)
            print(f"  -> 节点 #{i}: {node['server']}:{node['server_port']} ({node['country_short']}), 延迟={node['latency_ms']}ms", flush=True)

        config = v2s.build_singbox_config(
            final_endpoints,
            mixed_listen="127.0.0.1",
            mixed_port=args.mixed_port,
        )
        Path(args.output).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        print(f"[VPNGate] 已写入最终 sing-box 配置: {args.output} (监听 127.0.0.1:{args.mixed_port})", flush=True)
        return 0
    else:
        print("[VPNGate] 警告: 未找到 200 节点，使用前 3 个存活节点兜底...", file=sys.stderr)
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

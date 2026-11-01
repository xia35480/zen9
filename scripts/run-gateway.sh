#!/usr/bin/env bash
# 一台 runner 的生命周期（VPNGate OpenVPN 版）：
#   检查 sing-box -> 起网关 -> 起隧道 -> 真 chat 探活 -> 周期探活 -> 到点交班。
set -Eeuo pipefail

ROOT="${GITHUB_WORKSPACE:-$PWD}"
RUN="$ROOT/run"
BIN="$ROOT/bin"
mkdir -p "$RUN"

GW_LOG="$RUN/gateway.log"
GW_STDIO="$RUN/gateway.stdio.log"
CF_LOG="$RUN/cloudflared.log"
FLAG="$RUN/rotate.flag"
REASON="$RUN/rotate.reason"

PORT="${PORT:-8081}"
PROBE_MODEL="${PROBE_MODEL:-deepseek-v4.1-flash-free}"
PROBE_INTERVAL="${PROBE_INTERVAL_SEC:-300}"
MAX_RUN="${MAX_RUN_SEC:-13500}"

PROBE_PAYLOAD="$(printf '{"model":"%s","messages":[{"role":"system","content":"You are opencode, a coding agent. Answer concisely."},{"role":"user","content":"用一句话说明你能做什么。"},{"role":"assistant","content":"我可以帮你读写代码、运行命令、排查问题。"},{"role":"user","content":"好，只回复：ok"}],"max_tokens":128,"stream":true}' "$PROBE_MODEL")"

if [ -f "/tmp/vpngate_ready" ]; then
  export HTTPS_PROXY="http://127.0.0.1:18080" HTTP_PROXY="http://127.0.0.1:18080" ALL_PROXY="http://127.0.0.1:18080"
  export NO_PROXY="127.0.0.1,localhost"
elif [ -n "${PROXY_URL:-}" ]; then
  export HTTPS_PROXY="$PROXY_URL" HTTP_PROXY="$PROXY_URL"
fi

GW_PID=""
CF_PID=""
WATCH_PID=""
PUBLIC_URL=""
ok_count=0
fail_count=0
limit_count=0

say()  { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
note() { say "NOTE $*";  echo "::notice::$*"; }
warn() { say "WARN $*";  echo "::warning::$*"; }

try_vpngate_switch() {
  if [ -f "/tmp/verified_nodes.json" ]; then
    say "VPNGate: 检测到 429，尝试热切换到下一个已验证 200 节点..."
    python3 scripts/switch_vpngate_node.py || true
    sleep 2
    local new_ip
    new_ip="$(curl -s --max-time 6 -x http://127.0.0.1:18080 https://api.ipify.org 2>/dev/null || echo '?')"
    say "VPNGate: 切换完毕，当前出口 IP=$new_ip"
    printf '%s\n' "$new_ip" > "$RUN/egress-ip.txt"
    return 0
  fi
  return 1
}

curr_ip="$(curl -s --max-time 6 https://api.ipify.org 2>/dev/null || echo '?')"
printf '%s\n' "$curr_ip" > "$RUN/egress-ip.txt"
say "VPNGate 当前出口 IP=$curr_ip"

stop_proc() {
  local pid="$1" name="$2" i
  if [ -z "$pid" ]; then return 0; fi
  if ! kill -0 "$pid" 2>/dev/null; then return 0; fi
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 15); do
    if ! kill -0 "$pid" 2>/dev/null; then
      say "$name 已退出（${i}s）"
      return 0
    fi
    sleep 1
  done
  warn "$name 15s 没退，SIGKILL"
  kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
  local rc=$?
  trap - EXIT
  stop_proc "$CF_PID" cloudflared
  stop_proc "$GW_PID" gateway
  stop_proc "$WATCH_PID" log-watcher
  wait 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

finish_stats() {
  printf '%dh%02dm%02ds\n' $((SECONDS / 3600)) $(((SECONDS % 3600) / 60)) $((SECONDS % 60)) > "$RUN/uptime.txt"
  printf 'ok=%d limit=%d fail=%d\n' "$ok_count" "$limit_count" "$fail_count" > "$RUN/probe-stats.txt"
}

rotate() {
  local reason="$1" fast="${2:-}" floor=180
  if [ "$fast" = "fast" ]; then floor=0; fi
  printf '%s\n' "$reason" > "$FLAG"
  note "交班：$reason"
  finish_stats
  if [ "$SECONDS" -lt "$floor" ]; then
    say "起步过快，等 $((floor - SECONDS))s 再交班"
    sleep $((floor - SECONDS))
  fi
  exit 0
}

start_gateway() {
  PORT="$PORT" \
  LOG_FILE="$GW_LOG" \
  SHIM_SESSION_FILE="$RUN/shim_sessions.json" \
  DIRECT_DIAG=1 \
  DIRECT_DEBUG=0 \
  DIRECT_CONCURRENCY=16 \
  DIRECT_FREELIMIT_COOLDOWN=0 \
  DIRECT_FRESH_PER_TURN="${DIRECT_FRESH_PER_TURN:-0}" \
  ZEN_TLS=bun \
  ZEN_RUN_ID="${GITHUB_RUN_ID:-}" \
  DIRECT_SIDECAR=off \
  "$BIN/zen-direct" >>"$GW_STDIO" 2>&1 &
  GW_PID=$!
  say "gateway pid=$GW_PID port=$PORT model=$PROBE_MODEL"
}

http_code() {
  local url="$1" t="${2:-5}" c
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time "$t" "$url" 2>/dev/null || true)"
  printf '%s' "${c:-000}"
}

wait_local_health() {
  local deadline=$((SECONDS + ${1:-120}))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(http_code "http://127.0.0.1:$PORT/health" 5)" = "200" ]; then return 0; fi
    if ! kill -0 "$GW_PID" 2>/dev/null; then return 1; fi
    sleep 2
  done
  return 1
}

start_tunnel() {
  : > "$CF_LOG"
  if [ -n "${CF_TUNNEL_TOKEN:-}" ] && [ "${CF_TUNNEL_TOKEN}" != "quick" ] && [ "${CF_TUNNEL_TOKEN}" != "none" ]; then
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
      "$BIN/cloudflared" tunnel --no-autoupdate --loglevel info run --token "$CF_TUNNEL_TOKEN" >>"$CF_LOG" 2>&1 &
    CF_PID=$!
    if [ -n "${ZEN_PUBLIC_HOST:-}" ]; then PUBLIC_URL="https://$ZEN_PUBLIC_HOST"; fi
    say "named tunnel pid=$CF_PID host=${PUBLIC_URL:-<未设置 ZEN_PUBLIC_HOST>}"
    if [ -z "$PUBLIC_URL" ]; then
      local j
      for j in $(seq 1 10); do
        PUBLIC_URL="$(grep -oE '"hostname":"[^"]+"' "$CF_LOG" 2>/dev/null | head -n1 | sed -E 's/.*:"([^"]+)"/\1/' || true)"
        if [ -n "$PUBLIC_URL" ]; then PUBLIC_URL="https://$PUBLIC_URL"; break; fi
        if ! kill -0 "$CF_PID" 2>/dev/null; then break; fi
        sleep 2
      done
      if [ -n "$PUBLIC_URL" ]; then
        note "从隧道配置里读到域名：$PUBLIC_URL"
      else
        warn "没设 ZEN_PUBLIC_HOST，也没从隧道配置里读到域名，公网自检将跳过"
      fi
    fi
  else
    warn "没有 CF_TUNNEL_TOKEN，用临时隧道（URL 每次都会变）"
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
      "$BIN/cloudflared" tunnel --no-autoupdate --loglevel info --url "http://127.0.0.1:$PORT" >>"$CF_LOG" 2>&1 &
    CF_PID=$!
    local i
    for i in $(seq 1 60); do
      PUBLIC_URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$CF_LOG" 2>/dev/null | head -n1 || true)"
      if [ -n "$PUBLIC_URL" ]; then break; fi
      if ! kill -0 "$CF_PID" 2>/dev/null; then warn "cloudflared 提前退出"; break; fi
      sleep 2
    done
  fi
  if [ -n "$PUBLIC_URL" ]; then printf '%s\n' "$PUBLIC_URL" > "$RUN/public-url.txt"; fi
}

wait_public_health() {
  if [ -z "$PUBLIC_URL" ]; then return 0; fi
  local deadline=$((SECONDS + 180))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(http_code "$PUBLIC_URL/health" 10)" = "200" ]; then
      note "公网已通：$PUBLIC_URL"
      return 0
    fi
    sleep 3
  done
  return 1
}

watch_logs() {
  (
    tail -n 0 -F "$GW_LOG" 2>/dev/null \
      | grep --line-buffered -E 'FreeUsageLimitError|free-usage 429 .*turns=' \
      | while IFS= read -r line; do
          say "LOG-429 $line"
          printf '%s\n' "$line" > "$REASON"
        done
  ) &
  WATCH_PID=$!
}

probe_once() {
  local base="${1:-http://127.0.0.1:$PORT}"
  local max="${2:-90}"
  local out="$RUN/probe.json"
  PROBE_CODE="$(curl -sS -o "$out" -w '%{http_code}' --max-time "$max" \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer public' \
    -H 'User-Agent: zen-probe' \
    --data-binary "$PROBE_PAYLOAD" \
    --dump-header "$RUN/probe.hdr" \
    "$base/v1/chat/completions" 2>>"$RUN/probe.err" || echo 000)"
  PROBE_BODY="$(head -c 300 "$out" 2>/dev/null || true)"
  PROBE_BODY="${PROBE_BODY//$'\n'/ }"
}

verdict() {
  if [ "$PROBE_CODE" = "200" ]; then printf 'ok'; return; fi
  if [ "$PROBE_CODE" = "429" ]; then printf 'limit'; return; fi
  case "$PROBE_BODY" in
    *FreeUsageLimitError*) printf 'limit'; return ;;
  esac
  printf 'fail'
}

dump_boot_diag() {
  say "--- 网关启动日志 ---"
  head -6 "$GW_STDIO" 2>/dev/null | while IFS= read -r l; do say "gw| $l"; done
  if [ -s "$RUN/probe.hdr" ]; then
    say "--- 探针响应头 ---"
    grep -iE '^(HTTP/|x-|cf-|retry-after)' "$RUN/probe.hdr" 2>/dev/null | head -8 | while IFS= read -r l; do say "hdr| $l"; done
  fi
}

say "run start pid=$$ max=${MAX_RUN}s probe_interval=${PROBE_INTERVAL}s (VPNGate 模式)"

start_gateway
if ! wait_local_health 120; then
  tail -n 40 "$GW_LOG" 2>/dev/null || true
  rotate "本地 /health 120s 没起来"
fi

watch_logs

# 优先执行本地真 chat 探针：验证网关 + VPNGate sing-box 出口是否真正拿到 200
BOOT_BASE="http://127.0.0.1:$PORT"
BOOT_TRIES=3
boot_ok=0

attempt=0
while [ "$attempt" -lt "$BOOT_TRIES" ]; do
  attempt=$((attempt + 1))
  probe_once "$BOOT_BASE"
  v="$(verdict)"
  say "boot probe (local) #$attempt/$BOOT_TRIES -> $PROBE_CODE ($v)"
  case "$v" in
    ok) boot_ok=1; break ;;
    limit)
      if [ "$attempt" -lt "$BOOT_TRIES" ]; then
        warn "VPNGate 出口命中 429，尝试热切换下一个已验证节点 (第 $attempt/$BOOT_TRIES 次)..."
        try_vpngate_switch || true
        sleep 2
      else
        dump_boot_diag
        rotate "起手本地探测 429（换节点试了 $BOOT_TRIES 次）：${PROBE_BODY:0:200}" fast
      fi
      ;;
    *)
      if [ "$attempt" -ge "$BOOT_TRIES" ]; then
        dump_boot_diag
        rotate "起手本地探测 $BOOT_TRIES 次没拿到 200（最后一次 $PROBE_CODE）"
      fi
      sleep 2
      ;;
  esac
done
if [ "$boot_ok" = "0" ]; then
  rotate "起手探测 $BOOT_TRIES 次没拿到 200（最后一次 $PROBE_CODE）"
fi
ok_count=$((ok_count + 1))
note "网关就绪（VPNGate 本地 chat 200），开始起隧道"

start_tunnel
if [ -n "$PUBLIC_URL" ]; then
  note "验证公网隧道：$PUBLIC_URL/health"
  tunnel_ok=0
  t=0
  while [ "$t" -lt "$BOOT_TRIES" ]; do
    t=$((t + 1))
    code="$(http_code "$PUBLIC_URL/health" 10)"
    say "tunnel check #$t/$BOOT_TRIES -> $code"
    if [ "$code" = "200" ]; then tunnel_ok=1; break; fi
    sleep 3
  done
  if [ "$tunnel_ok" = "1" ]; then
    note "公网已通：$PUBLIC_URL"
  else
    warn "公网 /health 没回到 200（最后一次 $code），可能是新域名/回源解析中；本地 chat 200 已就绪，继续服务"
  fi
fi
note "IP 与出口验证完毕，开始服务"

next_probe=$((SECONDS + PROBE_INTERVAL))
gw_restarts=0
cf_restarts=0

while :; do
  sleep 15

  if [ -s "$REASON" ]; then
    say "捕获到日志 429，尝试 VPNGate 热切换下一个节点自愈..."
    : > "$REASON"
    try_vpngate_switch || true
    probe_once "$BOOT_BASE" 30
    if [ "$(verdict)" != "ok" ]; then
      rotate "日志命中 429 且换节点后仍失败" fast
    else
      say "VPNGate 换节点成功自愈！"
    fi
  fi

  if [ "$SECONDS" -ge "$MAX_RUN" ]; then
    rotate "到点交班（已跑 ${SECONDS}s）"
  fi

  if ! kill -0 "$GW_PID" 2>/dev/null; then
    gw_restarts=$((gw_restarts + 1))
    warn "gateway 进程没了（第 $gw_restarts 次）"
    if [ "$gw_restarts" -gt 3 ]; then rotate "gateway 反复退出"; fi
    start_gateway
    wait_local_health 120 || rotate "gateway 重启后 /health 不通"
  fi

  if ! kill -0 "$CF_PID" 2>/dev/null; then
    cf_restarts=$((cf_restarts + 1))
    warn "cloudflared 进程没了（第 $cf_restarts 次），重连"
    if [ "$cf_restarts" -gt 5 ]; then rotate "cloudflared 反复退出"; fi
    start_tunnel
    wait_public_health || warn "重连后公网还没通，继续等"
  fi

  if [ "$SECONDS" -ge "$next_probe" ]; then
    probe_once
    v="$(verdict)"
    case "$v" in
      ok)
        ok_count=$((ok_count + 1))
        fail_count=0
        limit_count=0
        ;;
      limit)
        limit_count=$((limit_count + 1))
        warn "周期探测 429，自动切换下一个 VPNGate 节点自愈..."
        try_vpngate_switch || true
        probe_once
        if [ "$(verdict)" = "ok" ]; then
          say "VPNGate 换节点成功自愈！"
          ok_count=$((ok_count + 1))
          fail_count=0
          limit_count=0
        elif [ "$limit_count" -ge 2 ]; then
          rotate "连续 $limit_count 次周期探测 429" fast
        fi
        ;;
      *)
        fail_count=$((fail_count + 1))
        warn "周期探测 $PROBE_CODE（连续失败 $fail_count/3）"
        ;;
    esac
    if [ "$fail_count" -ge 3 ]; then
      rotate "连续 3 次探测非 200（最后 $PROBE_CODE）"
    fi
    next_probe=$((SECONDS + PROBE_INTERVAL))
    finish_stats
  fi
done

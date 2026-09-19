#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qwen3guard-l2-sidecar.py —— 输出侧 L2 语义分类器两段式侧车（llama.cpp 驱动）

D8 议题二 T1=a 两段式契约＋议题三运行时（Q8_0＋两段式＋前缀命中部署形态）落地，
供 tee-infer `-output-guard-l2-url` 接线。

形态：Qwen3Guard-Gen-0.6B Q8_0 GGUF 由 llama-server 承载（部署前提见 D8 §3.3：
启动预热公共前缀＋--slot-save-path slot 前缀缓存常驻，归运维/取数脚本，本侧车不管）；
本侧车渲染 chat 模板 → POST <llama>/completion stream=true 累积解析：
  - `Safety:` 行完整即 flush 文档 1（轻段 {"blocked": bool}）——首帧放行判定依据（T1）；
  - 完整输出后 flush 文档 2（完整段 {"blocked","category","confidence":1.0,"match":""}）；
  - 不设 stop（T3 策略 i：slot 占用至完整输出保类目，E[S]＝完整时长）。

契约（tee-infer outputguard.go v2；与 scripts/og13-l2-stub.py v1 单段向后兼容）：
  POST {"text": "..."} → 200，响应体＝换行分隔两个 JSON 文档（文档 1 即到即 flush）。
  blocked 映射（对齐插件 riskLevelBar=Unsafe 默认口径）：Safety: Unsafe → true；
    Safe / Controversial → false（Controversial 放行）。
  category＝Qwen 原生 Categories 行原文（内部 31 类映射由 P-CATEGORY-MAP 在 Go 侧承担）。
  confidence：命中固定 1.0（D8 裁定：贪心解码＝模型硬决策）。

降级（fail-closed，D8 T5）：
  - llama-server 不可达 / 流中断且 Safety 行未出 / 完整输出无 Safety 行 → 500
    （适配层 bad_status 失败哨兵）；
  - 轻段 false 后完整段失败 → 文档 2 {"blocked": false}（判定已给出＝正常 miss，T5）；
  - 轻段 true 后完整段失败（类目未定）→ 文档 2 {"error": ...}——blocked 零值 false 与
    轻段 true 矛盾 → 适配层 bad_response 失败哨兵（held 槽位超时降级，fail-closed）。
    不可发 {"blocked": true}：该形态经 v1/v2 兼容解析会落 cat=""＝miss，等于放行。

用法：
  # 1) 先起 llama-server（Q8_0；slot 前缀缓存常驻；-np 并发＝槽位数）：
  #    llama-server -m <Qwen3Guard-Gen-0.6B-Q8_0.gguf> --host 127.0.0.1 --port 19110 \
  #                  -np 8 -c 2048 --slot-save-path <dir> -fa
  # 2) 起本侧车（tokenizer 仅用于 chat 模板渲染，与 qwen3guard-server.py 同源）：
  #    python scripts/qwen3guard-l2-sidecar.py --port 19112
  # 3) tee-infer 接线：-output-guard-l2-url http://127.0.0.1:19112
"""

import argparse
import json
import os
import re
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 固定 user prompt（生产形态：输出侧句级审查不携带原始用户问句——adapter 只送 {"text"}，
# 侧车以固定 user turn 合成模板，与 .tools spike_common.FIXED_USER 一致，
# 保证公共前缀稳定、llama-server slot 前缀缓存可命中）。
FIXED_USER = "帮我查一下明天北京的天气，并给我一些出行建议。"

# 与插件 guard.go / spike_common 同口径的 Safety/Categories 行解析（行首、多行模式）。
SAFETY_RE = re.compile(r"(?mi)^Safety:\s*(Safe|Unsafe|Controversial)\b")
CATS_RE = re.compile(r"(?mi)^Categories:\s*(.+)$")

# 流式触发用：Safety 行**已完整**（标签同行且行尾换行已到）才 flush 轻段，
# 防部分 token（如 "Saf"）误触发；\s* 在多行模式可跨行，故限定 [ \t] 同行匹配。
SAFETY_LINE_DONE_RE = re.compile(r"(?mi)^Safety:[ \t]*(Safe|Unsafe|Controversial)[^\n]*\n")

# 进程级配置（main 填充，handler 只读）。
CFG = {
    "llama_url": "http://127.0.0.1:19110",
    "llama_timeout": 30.0,  # 上游单请求超时（tee-infer 侧另有自己的 2s 级超时约束）
    "n_predict": 64,        # 对齐 §10.2 max_new_tokens=64（完整输出 7-8 token 即 EOS 早停）
}

TOK = None  # tokenizer（仅 chat 模板渲染用，不加载模型权重）
CALLS = 0


def render(text):
    """与 scripts/qwen3guard-server.py generate() 完全一致的模板渲染。"""
    msgs = [
        {"role": "user", "content": FIXED_USER},
        {"role": "assistant", "content": text},
    ]
    return TOK.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)


def llama_completion_stream(prompt):
    """POST llama-server /completion stream=true，逐 token 产出增量 content。

    贪心解码（temperature=0.0, top_k=1）且不设 stop——T3 策略 i：slot 占用至完整输出。
    """
    payload = json.dumps({
        "prompt": prompt,
        "n_predict": CFG["n_predict"],
        "temperature": 0.0,
        "top_k": 1,
        "stream": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        CFG["llama_url"] + "/completion", data=payload,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=CFG["llama_timeout"]) as resp:
        for raw in resp:  # SSE：每事件一行 `data: {...}`
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if not data or data == "[DONE]":
                continue
            try:
                ev = json.loads(data)
            except json.JSONDecodeError:
                continue
            if ev.get("content"):
                yield ev["content"]
            if ev.get("stop") is True:
                return


class L2SidecarHandler(BaseHTTPRequestHandler):
    # 抑制默认访问日志（与 og13-l2-stub 一致）；逐调用摘要另行打印。
    def log_message(self, fmt, *args):
        return

    # ---- 响应原语 ----

    def _send_json(self, code, payload):
        """单文档一次性响应（错误/健康检查路径）。"""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _begin_stream(self):
        """两段式响应头（无 Content-Length：HTTP/1.0 连接关闭定界）。"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()

    def _write_doc(self, doc):
        """写一个 JSON 文档（换行分隔）并 flush——轻段即出即达。"""
        self.wfile.write((json.dumps(doc, ensure_ascii=False) + "\n").encode("utf-8"))
        self.wfile.flush()

    # ---- HTTP 入口 ----

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") in ("/healthz", "/"):
            self._send_json(200, {"status": "ok", "backend": "llamacpp-twostage",
                                  "llama_url": CFG["llama_url"]})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        global CALLS
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            req = json.loads(raw.decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": "bad json: %s" % exc})
            return
        text = req.get("text")
        if not isinstance(text, str):
            self._send_json(400, {"error": "field 'text' (string) required"})
            return

        CALLS += 1
        t0 = time.perf_counter()
        buf = ""
        light_sent = False
        light_blocked = None
        t_light = None
        try:
            for chunk in llama_completion_stream(render(text)):
                buf += chunk
                if not light_sent:
                    m = SAFETY_LINE_DONE_RE.search(buf)
                    if m:
                        light_blocked = m.group(1) == "Unsafe"
                        self._begin_stream()
                        self._write_doc({"blocked": light_blocked})
                        light_sent = True
                        t_light = time.perf_counter() - t0
        except Exception as exc:  # noqa: BLE001  上游不可达/流中断
            self._on_upstream_error(light_sent, light_blocked, exc)
            self._log(text, t_light, None, "error: %s" % exc)
            return
        self._finish(buf, light_sent, light_blocked)
        safety = SAFETY_RE.search(buf)
        cats = CATS_RE.search(buf)
        self._log(text, t_light, time.perf_counter() - t0,
                 "safety=%s cats=%s" % (safety.group(1) if safety else None,
                                        cats.group(1).strip() if cats else None))

    # ---- 两段式状态处置 ----

    def _on_upstream_error(self, light_sent, light_blocked, exc):
        """上游失败（不可达/流中断）的 fail-closed 处置。

        轻段未出 → 500（适配层 bad_status 哨兵）；
        轻段 false → 文档 2 {"blocked": false}（判定已给出＝正常 miss，D8 T5）；
        轻段 true → 文档 2 {"error": ...}（与轻段矛盾 → bad_response 哨兵，类目未定
                    fail-closed；不可发 {"blocked": true}——无 category 会经 v1/v2
                    兼容解析落 miss，等于放行）。
        """
        if not light_sent:
            self._send_json(500, {"error": "llama upstream failed: %s" % exc})
            return
        try:
            if light_blocked:
                self._write_doc({"error": "full segment failed after blocked verdict: %s" % exc})
            else:
                self._write_doc({"blocked": False})
        except (BrokenPipeError, ConnectionResetError):
            pass  # tee-infer 侧超时先断开：判定哨兵已无法送达，止于日志

    def _finish(self, buf, light_sent, light_blocked, t0, t_light):
        """完整输出到达后的文档 2 组装（文档 1 若未发则在此补发）。"""
        safety = SAFETY_RE.search(buf)
        cats = CATS_RE.search(buf)
        # Safety 行缺失（含流正常结束但输出畸形）→ 500 哨兵（轻段未出才能走此分支）。
        if safety is None:
            self._send_json(500, {"error": "no Safety line in model output",
                                  "output": buf[:200]})
            return
        if not light_sent:  # 流内未触发（如末行无换行即 EOS）：补发轻段，两段同批写出
            light_blocked = safety.group(1) == "Unsafe"
            self._begin_stream()
            self._write_doc({"blocked": light_blocked})
        blocked = safety.group(1) == "Unsafe"
        try:
            if blocked:
                cats_line = cats.group(1).strip() if cats else ""
                if not cats_line or cats_line.lower() == "none":
                    # Unsafe 但类目未定（Categories 缺失/None）＝无法执行动作表 →
                    # 矛盾哨兵文档，fail-closed（同 _on_upstream_error 轻段 true 路径）。
                    self._write_doc({"error": "categories missing for unsafe verdict"})
                else:
                    self._write_doc({"blocked": True, "category": cats_line,
                                     "confidence": 1.0, "match": ""})
            else:
                self._write_doc({"blocked": False})
        except (BrokenPipeError, ConnectionResetError):
            pass  # tee-infer 侧超时先断开：轻段已送达，完整段迟到丢弃（既有机制）

    def _log(self, text, t_light, t_full, tail):
        print("[l2-sidecar] #%d len=%d light=%s full=%s %s"
              % (CALLS, len(text),
                 "%.3fs" % t_light if t_light is not None else "-",
                 "%.3fs" % t_full if t_full is not None else "-", tail), flush=True)


def main():
    ap = argparse.ArgumentParser(description="qwen3guard L2 two-stage sidecar (llama.cpp)")
    ap.add_argument("--model-dir", default=os.path.join(".tools", "models", "Qwen3Guard-Gen-0.6B"),
                    help="tokenizer 目录（仅 chat 模板渲染，同 qwen3guard-server.py）")
    ap.add_argument("--port", type=int, default=19112,
                    help="监听端口 (default: 19112；og13-l2-stub=19099、llama-server spike=19110)")
    ap.add_argument("--llama-url", default="http://127.0.0.1:19110",
                    help="llama-server 基地址 (default: http://127.0.0.1:19110)")
    ap.add_argument("--llama-timeout", type=float, default=30.0,
                    help="llama-server 单请求超时秒 (default: 30)")
    ap.add_argument("--n-predict", type=int, default=64,
                    help="n_predict 上限 (default: 64，完整输出 7-8 token 即 EOS 早停)")
    args = ap.parse_args()

    global TOK
    if not os.path.isdir(args.model_dir):
        print("[l2-sidecar] model dir not found: %s" % args.model_dir, flush=True)
        return 1
    from transformers import AutoTokenizer  # noqa: PLC0415
    print("[l2-sidecar] loading tokenizer from %s ..." % args.model_dir, flush=True)
    t0 = time.time()
    TOK = AutoTokenizer.from_pretrained(args.model_dir)
    print("[l2-sidecar] tokenizer loaded in %.1fs" % (time.time() - t0), flush=True)

    CFG["llama_url"] = args.llama_url.rstrip("/")
    CFG["llama_timeout"] = args.llama_timeout
    CFG["n_predict"] = args.n_predict

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), L2SidecarHandler)
    print("[l2-sidecar] listening on 127.0.0.1:%d -> %s/completion (two-stage; "
          "n_predict=%d, greedy, no-stop=T3 policy i)" % (args.port, CFG["llama_url"],
                                                          CFG["n_predict"]), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("[l2-sidecar] stopped", flush=True)
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

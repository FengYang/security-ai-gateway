"""Go/Python 协议双实现交叉一致性测试（M5-1 验收 + P1a 信封升级）。

验证 Go 编码 → Python 解码、Python 编码 → Go 解码 完全一致；
P1a 起增加段① 加密信封跨语言一致性（双向加解密、方向/端点/篡改拒绝、
反重放窗口决策比对、SSE 流序号校验）。
运行：python protocol/python/cross_test.py（需 Go 工具链生成参考数据）。
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import otpmask_protocol as proto


def main() -> int:
    k_sig = b"cross-test-k-sig-32-byte-key!!"
    req_id = "cross-001"
    ts = time.time_ns()
    # 使用 R=2^32 域内值（协议实际值域；避免 JSON 中转的 float64 精度问题）
    vectors = [[1, 2, 3, 4294967295], [4294967294, 0, 42]]
    nonce = b"cross-nonce-16b!!"
    # M9-4 密文文本通道（OTP-Mask 逐字节密文示例）
    cipher_text = bytes([0xA1, 0xB2, 0xC3, 0xD4, 0xE5])

    sig = proto.sign_request(k_sig, req_id, ts, "mock", 128, nonce, vectors, cipher_text)
    py_enc = proto.encode_request(req_id, ts, "mock", 128, nonce, vectors, sig, cipher_text)

    # Go 解码 Python 编码的请求（通过 Go 测试程序）
    go_dec = run_go_decode("request", py_enc)
    assert go_dec["request_id"] == req_id, "request_id 不一致"
    assert go_dec["timestamp_ns"] == ts, "timestamp_ns 不一致"
    assert go_dec["cipher_vectors"] == vectors, "cipher_vectors 不一致"
    assert bytes.fromhex(go_dec["cipher_text"]) == cipher_text, "cipher_text 不一致"
    assert go_dec["signature"] == sig.hex(), "signature 不一致"
    print("[PASS] Python 编码 → Go 解码一致（含 cipher_text）")

    # Go 编码 → Python 解码
    go_enc = run_go_encode("request", {
        "request_id": req_id, "timestamp_ns": ts, "model": "mock",
        "max_new_tokens": 128, "nonce": nonce.hex(),
        "cipher_vectors": vectors, "cipher_text": cipher_text.hex(),
    }, k_sig.hex())
    dec = proto.decode_request(bytes.fromhex(go_enc))
    assert dec["request_id"] == req_id, "request_id 不一致"
    assert dec["cipher_vectors"] == vectors, "cipher_vectors 不一致"
    assert dec["cipher_text"] == cipher_text, "cipher_text 不一致"
    assert proto.verify_request(k_sig, dec), "Go 编码请求签名校验失败"
    print("[PASS] Go 编码 → Python 解码 + 签名校验一致（含 cipher_text）")

    # 6.2 协议扩展：engine_type/attest_type 双端一致
    sig_ext = proto.sign_request(k_sig, req_id, ts, "qwen2.5-0.5b", 32, nonce, vectors, b"")
    py_enc_ext = proto.encode_request(req_id, ts, "qwen2.5-0.5b", 32, nonce, vectors, sig_ext,
                                      b"", proto.ENGINE_TYPE_MASKED_VECTOR, proto.ATTEST_TYPE_QUOTE)
    go_dec_ext = run_go_decode("request", py_enc_ext)
    assert go_dec_ext["engine_type"] == proto.ENGINE_TYPE_MASKED_VECTOR, "engine_type 不一致"
    assert go_dec_ext["attest_type"] == proto.ATTEST_TYPE_QUOTE, "attest_type 不一致"
    go_enc_ext = run_go_encode("request", {
        "request_id": req_id, "timestamp_ns": ts, "model": "qwen2.5-0.5b",
        "max_new_tokens": 32, "nonce": nonce.hex(),
        "cipher_vectors": vectors, "cipher_text": "",
        "engine_type": proto.ENGINE_TYPE_MASKED_VECTOR, "attest_type": proto.ATTEST_TYPE_QUOTE,
    }, k_sig.hex())
    dec_ext = proto.decode_request(bytes.fromhex(go_enc_ext))
    assert dec_ext["engine_type"] == proto.ENGINE_TYPE_MASKED_VECTOR, "Go→Py engine_type 不一致"
    assert dec_ext["attest_type"] == proto.ATTEST_TYPE_QUOTE, "Go→Py attest_type 不一致"
    print("[PASS] 6.2 协议扩展 engine_type/attest_type 双端一致")

    # P2/P5：text 载荷（text_payload/stream）双端一致
    text_payload = b'[{"role":"user","content":"\\u4f60\\u597d"}]'
    sig_txt = proto.sign_request(k_sig, req_id, ts, "mock", 256, nonce, [], b"",
                                 text_payload, True)
    py_enc_txt = proto.encode_request(req_id, ts, "mock", 256, nonce, [], sig_txt,
                                      b"", proto.ENGINE_TYPE_TEE_GPU, proto.ATTEST_TYPE_QUOTE,
                                      text_payload, True)
    go_dec_txt = run_go_decode("request", py_enc_txt)
    assert go_dec_txt["engine_type"] == proto.ENGINE_TYPE_TEE_GPU, "text 请求 engine_type 不一致"
    assert go_dec_txt["attest_type"] == proto.ATTEST_TYPE_QUOTE, "text 请求 attest_type 不一致"
    assert bytes.fromhex(go_dec_txt["text_payload"]) == text_payload, "text_payload 不一致"
    assert go_dec_txt["stream"] is True, "stream 不一致"
    assert go_dec_txt["signature"] == sig_txt.hex(), "text 请求签名不一致"
    go_enc_txt = run_go_encode("request", {
        "request_id": req_id, "timestamp_ns": ts, "model": "mock",
        "max_new_tokens": 256, "nonce": nonce.hex(),
        "cipher_vectors": [], "cipher_text": "",
        "engine_type": proto.ENGINE_TYPE_TEE_GPU, "attest_type": proto.ATTEST_TYPE_QUOTE,
        "text_payload": text_payload.hex(), "stream": True,
    }, k_sig.hex())
    dec_txt = proto.decode_request(bytes.fromhex(go_enc_txt))
    assert dec_txt["text_payload"] == text_payload, "Go→Py text_payload 不一致"
    assert dec_txt["stream"] is True, "Go→Py stream 不一致"
    assert proto.verify_request(k_sig, dec_txt), "Go 编码 text 请求签名校验失败"
    print("[PASS] P2/P5 text 载荷（text_payload/stream）双端一致")

    # 旧格式向后兼容：仅 engine_type/attest_type 的请求仍可解码（无 text 字段）
    sig_old = proto.sign_request(k_sig, req_id, ts, "mock", 32, nonce, vectors, b"")
    py_enc_old = proto.encode_request(req_id, ts, "mock", 32, nonce, vectors, sig_old,
                                      b"", proto.ENGINE_TYPE_MASKED_VECTOR, proto.ATTEST_TYPE_QUOTE)
    dec_old = proto.decode_request(py_enc_old)
    assert dec_old["text_payload"] == b"" and dec_old["stream"] is False, "旧格式应无 text 字段"
    print("[PASS] 旧格式向后兼容（无 text 载荷字段）")

    # 响应交叉
    output = [7, 8, 9]
    resp_sig = proto_sign_response_py(k_sig, req_id, ts, output, 3)
    py_resp = proto.encode_response(req_id, ts, proto.STATUS_OK, output, 3, resp_sig)
    go_resp = run_go_decode("response", py_resp)
    assert go_resp["cipher_output"] == output, "响应 output 不一致"
    print("[PASS] Python 响应编码 → Go 解码一致")

    envelope_cross_tests()
    return 0


def envelope_cross_tests() -> None:
    """P1a 信封跨语言一致性：双向加解密 + 方向/上下文/篡改拒绝 + 重放/乱序窗口决策比对。"""
    k_enc = b"cross-test-k-enc-32-byte-key!!!"
    session_id = "cross-sess-001"
    endpoint = "/v1/infer"
    plaintext = "路线1段①信封跨语言测试 payload 🇨🇳".encode()
    plaintext_hex = plaintext.hex()

    # 1. Python 加密 → Go 解密（c2s / s2c 双方向）
    for direction in (proto.DIRECTION_C2S, proto.DIRECTION_S2C):
        counter = 42
        py_wire = proto.seal_envelope(k_enc, session_id, endpoint, direction, counter, plaintext)
        go_open = run_go_helper([
            "envelope_open", k_enc.hex(), session_id, endpoint, str(direction), py_wire.hex()])
        got = json.loads(go_open)
        assert bytes.fromhex(got["plaintext"]) == plaintext, f"方向 {direction} 明文不一致"
        assert got["counter"] == counter, f"方向 {direction} 计数器不一致"
    print("[PASS] Python 加密信封 → Go 解密一致（c2s/s2c）")

    # 2. Go 加密 → Python 解密
    for direction in (proto.DIRECTION_C2S, proto.DIRECTION_S2C):
        counter = 7
        go_wire = run_go_helper([
            "envelope_seal", k_enc.hex(), session_id, endpoint,
            str(direction), str(counter), plaintext_hex]).strip()
        pt, ctr = proto.open_envelope(k_enc, session_id, endpoint, direction, bytes.fromhex(go_wire))
        assert pt == plaintext, f"方向 {direction} Go→Py 明文不一致"
        assert ctr == counter, f"方向 {direction} Go→Py 计数器不一致"
    print("[PASS] Go 加密信封 → Python 解密一致（c2s/s2c）")

    # 3. 跨语言拒绝：Python 加密 c2s，Go 以 s2c 打开（降级/反射攻击）
    py_wire = proto.seal_envelope(k_enc, session_id, endpoint, proto.DIRECTION_C2S, 9, plaintext)
    try:
        run_go_helper(["envelope_open", k_enc.hex(), session_id, endpoint,
                       str(proto.DIRECTION_S2C), py_wire.hex()])
        raise AssertionError("方向不匹配未被 Go 拒绝")
    except RuntimeError:
        pass
    print("[PASS] Go 拒绝方向不匹配信封（防反射/降级）")

    # 4. 跨语言拒绝：Go 加密，Python 以错误端点打开（跨端点重放）
    go_wire = bytes.fromhex(run_go_helper([
        "envelope_seal", k_enc.hex(), session_id, endpoint,
        str(proto.DIRECTION_C2S), "11", plaintext_hex]).strip())
    try:
        proto.open_envelope(k_enc, session_id, "/key/issue", proto.DIRECTION_C2S, go_wire)
        raise AssertionError("跨端点重放未被 Python 拒绝")
    except ValueError:
        pass
    # 篡改密文尾部（GCM tag）
    tampered = bytearray(go_wire)
    tampered[-1] ^= 0xFF
    try:
        proto.open_envelope(k_enc, session_id, endpoint, proto.DIRECTION_C2S, bytes(tampered))
        raise AssertionError("篡改 tag 未被 Python 拒绝")
    except ValueError:
        pass
    print("[PASS] Python 拒绝跨端点重放与篡改信封")

    # 5. 反重放窗口决策比对（重放/乱序/越窗，含大步前进窗口重置）
    counters = [1, 2, 3, 2, 5, 4, 4, 10, 12, 11, 6, 100, 100, 12]
    go_decisions = json.loads(run_go_helper([
        "window_run", ",".join(str(c) for c in counters)]))
    py_window = proto.CounterWindow()
    py_decisions = []
    for c in counters:
        try:
            py_window.check(c)
            py_decisions.append({"counter": c, "ok": True})
        except ValueError:
            py_decisions.append({"counter": c, "ok": False})
    assert go_decisions == py_decisions, \
        f"反重放窗口决策不一致:\nGo:   {go_decisions}\nPy:   {py_decisions}"
    rejected = [d["counter"] for d in go_decisions if not d["ok"]]
    assert rejected == [2, 4, 100, 12], f"预期拒绝集不符: {rejected}"
    print("[PASS] Go/Python 反重放窗口决策一致（重放/乱序/越窗拒绝）")

    # 6. SSE 流序号严格递增（Python 侧；Go 侧见 envelope_test.go）
    proto.check_stream_sequence(0, 1)
    proto.check_stream_sequence(1, 2)
    for last, got in ((1, 1), (1, 3), (2, 1)):
        try:
            proto.check_stream_sequence(last, got)
            raise AssertionError(f"乱序分片 ({last}→{got}) 未被拒绝")
        except ValueError:
            pass
    print("[PASS] SSE 流序号严格递增校验一致")


def proto_sign_response_py(k_sig, req_id, ts, output, tokens):
    # 复用库内 verify 逻辑的签名构造（直接调用内部函数签名）
    mac = __import__("hmac").new(k_sig, digestmod=__import__("hashlib").sha256)
    mac.update(req_id.encode())
    mac.update(__import__("struct").pack(">Q", ts & 0xFFFFFFFFFFFFFFFF))
    mac.update(b"")
    import otpmask_protocol as p
    payload = bytearray()
    p._put_varint(payload, p.STATUS_OK)
    payload.extend(p.encode_vector(output))
    p._put_varint(payload, tokens)
    mac.update(bytes(payload))
    return mac.digest()


def run_go_decode(kind: str, data: bytes) -> dict:
    out = run_go_helper(["decode", kind, data.hex()])
    return json.loads(out)


def run_go_encode(kind: str, fields: dict, k_sig_hex: str) -> str:
    out = run_go_helper(["encode", kind, json.dumps(fields), k_sig_hex])
    return out.strip()


def run_go_helper(args: list) -> str:
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    helper = os.path.join(repo, "protocol", "go", "cmd", "cross_helper", "main.go")
    # 本机 Go 不在 PATH（默认安装于 Program Files）
    go_bin = os.environ.get("GO_BIN", r"C:\Program Files\Go\bin\go.exe")
    r = subprocess.run(
        [go_bin, "run", helper] + args,
        cwd=repo, capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        raise RuntimeError(f"Go helper 失败: {r.stderr}")
    return r.stdout


if __name__ == "__main__":
    sys.exit(main())

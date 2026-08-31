"""Go/Python 协议双实现交叉一致性测试（M5-1 验收）。

验证 Go 编码 → Python 解码、Python 编码 → Go 解码 完全一致。
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

    # 响应交叉
    output = [7, 8, 9]
    resp_sig = proto_sign_response_py(k_sig, req_id, ts, output, 3)
    py_resp = proto.encode_response(req_id, ts, proto.STATUS_OK, output, 3, resp_sig)
    go_resp = run_go_decode("response", py_resp)
    assert go_resp["cipher_output"] == output, "响应 output 不一致"
    print("[PASS] Python 响应编码 → Go 解码一致")
    return 0


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

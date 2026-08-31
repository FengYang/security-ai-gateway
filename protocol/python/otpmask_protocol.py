"""otpmask_protocol — 南向私有二进制协议 Python 镜像实现（M5）。

与 protocol/go/protocol.go 的 wire format 完全一致（Varint + length-prefixed），
用于 vLLM（Python）侧解码与交叉测试。权威定义：protocol/proto/otpmask.proto。
"""

import hmac
import hashlib
import struct

STATUS_OK = 0
STATUS_ERROR = 1
STATUS_RATE_LIMITED = 2
STATUS_MODEL_NOT_FOUND = 3

# 南向协议 wire 版本（5.2 版本一致性校验；与 protocol/go/protocol.go 的 Version 一致）
VERSION = "1.0.0"

REPLAY_WINDOW_NS = 30 * 1_000_000_000

# 6.2 协议扩展：engine_type / attest_type 枚举（可选字段，追加于 wire 末尾，向后兼容）
ENGINE_TYPE_TEE_GPU = "tee_gpu"          # 路线 1（缺省）
ENGINE_TYPE_MASKED_VECTOR = "masked_vector"  # 路线 2
ATTEST_TYPE_QUOTE = "quote"              # TEE 证明（生产默认）
ATTEST_TYPE_TOKEN = "token"              # MVP 凭证（向后兼容，测试/灰度）


def _put_varint(buf: bytearray, v: int) -> None:
    while v >= 0x80:
        buf.append((v & 0x7F) | 0x80)
        v >>= 7
    buf.append(v)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    v = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("varint truncated")
        b = data[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if b & 0x80 == 0:
            return v, pos
        shift += 7
        if shift >= 64:
            raise ValueError("varint overflow")


def _put_bytes(buf: bytearray, b: bytes) -> None:
    _put_varint(buf, len(b))
    buf.extend(b)


def _read_len_bytes(data: bytes, pos: int) -> tuple[bytes, int]:
    n, pos = _read_varint(data, pos)
    if len(data) - pos < n:
        raise ValueError("length-prefixed bytes truncated")
    return data[pos:pos + n], pos + n


def encode_vector(vec: list[int]) -> bytes:
    buf = bytearray()
    _put_varint(buf, len(vec))
    for x in vec:
        _put_varint(buf, x)
    return bytes(buf)


def decode_vector(data: bytes, pos: int) -> tuple[list[int], int]:
    n, pos = _read_varint(data, pos)
    vec = []
    for _ in range(n):
        x, pos = _read_varint(data, pos)
        vec.append(x)
    return vec, pos


def _payload_bytes(model: str, max_new_tokens: int, vectors: list[list[int]],
                   cipher_text: bytes = b"") -> bytes:
    buf = bytearray()
    _put_bytes(buf, model.encode())
    _put_varint(buf, max_new_tokens)
    _put_varint(buf, len(vectors))
    for v in vectors:
        buf.extend(encode_vector(v))
    _put_bytes(buf, cipher_text)  # M9-4 密文文本通道（可空）
    return bytes(buf)


def sign_message(k_sig: bytes, req_id: str, ts_ns: int, nonce: bytes, payload: bytes) -> bytes:
    mac = hmac.new(k_sig, digestmod=hashlib.sha256)
    mac.update(req_id.encode())
    mac.update(struct.pack(">Q", ts_ns & 0xFFFFFFFFFFFFFFFF))
    mac.update(nonce)
    mac.update(payload)
    return mac.digest()


def sign_request(k_sig: bytes, req_id: str, ts_ns: int, model: str,
                 max_new_tokens: int, nonce: bytes, vectors: list[list[int]],
                 cipher_text: bytes = b"") -> bytes:
    return sign_message(k_sig, req_id, ts_ns, nonce,
                        _payload_bytes(model, max_new_tokens, vectors, cipher_text))


def encode_request(req_id: str, ts_ns: int, model: str, max_new_tokens: int,
                   nonce: bytes, vectors: list[list[int]], signature: bytes,
                   cipher_text: bytes = b"", engine_type: str = "",
                   attest_type: str = "") -> bytes:
    buf = bytearray()
    _put_bytes(buf, req_id.encode())
    _put_varint(buf, ts_ns & 0xFFFFFFFFFFFFFFFF)
    _put_bytes(buf, model.encode())
    _put_varint(buf, max_new_tokens)
    _put_bytes(buf, nonce)
    _put_varint(buf, len(vectors))
    for v in vectors:
        buf.extend(encode_vector(v))
    _put_bytes(buf, cipher_text)
    _put_bytes(buf, signature)
    # 6.2 协议扩展（可选字段，追加于末尾；空串不编码，保持向后兼容）
    if engine_type:
        _put_bytes(buf, engine_type.encode())
        _put_bytes(buf, attest_type.encode())
    return bytes(buf)


def decode_request(data: bytes) -> dict:
    pos = 0
    req_id, pos = _read_len_bytes(data, pos)
    ts_ns, pos = _read_varint(data, pos)
    model, pos = _read_len_bytes(data, pos)
    max_new_tokens, pos = _read_varint(data, pos)
    nonce, pos = _read_len_bytes(data, pos)
    m, pos = _read_varint(data, pos)
    vectors = []
    for _ in range(m):
        v, pos = decode_vector(data, pos)
        vectors.append(v)
    cipher_text, pos = _read_len_bytes(data, pos)
    signature, pos = _read_len_bytes(data, pos)
    engine_type = b""
    attest_type = b""
    # 6.2 协议扩展（可选字段，缺省为空 = 旧格式请求，向后兼容）
    if pos < len(data):
        engine_type, pos = _read_len_bytes(data, pos)
        attest_type, _ = _read_len_bytes(data, pos)
    return {
        "request_id": req_id.decode(),
        "timestamp_ns": ts_ns,
        "model": model.decode(),
        "max_new_tokens": max_new_tokens,
        "nonce": nonce,
        "cipher_vectors": vectors,
        "cipher_text": cipher_text,
        "signature": signature,
        "engine_type": engine_type.decode(),
        "attest_type": attest_type.decode(),
    }


def verify_request(k_sig: bytes, req: dict) -> bool:
    got = req["signature"]
    want = sign_request(k_sig, req["request_id"], req["timestamp_ns"], req["model"],
                        req["max_new_tokens"], req["nonce"], req["cipher_vectors"],
                        req.get("cipher_text", b""))
    return hmac.compare_digest(got, want)


def encode_response(req_id: str, ts_ns: int, status: int, output: list[int],
                    tokens_generated: int, signature: bytes) -> bytes:
    buf = bytearray()
    _put_bytes(buf, req_id.encode())
    _put_varint(buf, ts_ns & 0xFFFFFFFFFFFFFFFF)
    _put_varint(buf, status)
    buf.extend(encode_vector(output))
    _put_varint(buf, tokens_generated)
    _put_bytes(buf, signature)
    return bytes(buf)


def decode_response(data: bytes) -> dict:
    pos = 0
    req_id, pos = _read_len_bytes(data, pos)
    ts_ns, pos = _read_varint(data, pos)
    status, pos = _read_varint(data, pos)
    output, pos = decode_vector(data, pos)
    tokens_generated, pos = _read_varint(data, pos)
    signature, _ = _read_len_bytes(data, pos)
    return {
        "request_id": req_id.decode(),
        "timestamp_ns": ts_ns,
        "status": status,
        "cipher_output": output,
        "tokens_generated": tokens_generated,
        "signature": signature,
    }


def verify_response(k_sig: bytes, resp: dict) -> bool:
    got = resp["signature"]
    mac = hmac.new(k_sig, digestmod=hashlib.sha256)
    mac.update(resp["request_id"].encode())
    mac.update(struct.pack(">Q", resp["timestamp_ns"] & 0xFFFFFFFFFFFFFFFF))
    mac.update(b"")
    payload = bytearray()
    _put_varint(payload, resp["status"])
    payload.extend(encode_vector(resp["cipher_output"]))
    _put_varint(payload, resp["tokens_generated"])
    mac.update(bytes(payload))
    return hmac.compare_digest(got, mac.digest)

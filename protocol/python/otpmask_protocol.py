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
ENGINE_TYPE_CMAAS = "cmaas"              # 路线 1：百炼 Confidential MaaS（P5）
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
                   cipher_text: bytes = b"", text_payload: bytes = b"",
                   stream: bool = False) -> bytes:
    buf = bytearray()
    _put_bytes(buf, model.encode())
    _put_varint(buf, max_new_tokens)
    _put_varint(buf, len(vectors))
    for v in vectors:
        buf.extend(encode_vector(v))
    _put_bytes(buf, cipher_text)  # M9-4 密文文本通道（可空）
    _put_bytes(buf, text_payload)  # P2/P5 text 载荷纳入签名
    _put_varint(buf, 1 if stream else 0)
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
                 cipher_text: bytes = b"", text_payload: bytes = b"",
                 stream: bool = False) -> bytes:
    return sign_message(k_sig, req_id, ts_ns, nonce,
                        _payload_bytes(model, max_new_tokens, vectors, cipher_text,
                                       text_payload, stream))


def encode_request(req_id: str, ts_ns: int, model: str, max_new_tokens: int,
                   nonce: bytes, vectors: list[list[int]], signature: bytes,
                   cipher_text: bytes = b"", engine_type: str = "",
                   attest_type: str = "", text_payload: bytes = b"",
                   stream: bool = False) -> bytes:
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
    # 6.2 协议扩展（可选字段，追加于末尾；空 engine_type 不编码，保持向后兼容）。
    # P2/P5：text 载荷请求必然声明 engine_type，故 text_payload/stream 随扩展段编码。
    if engine_type:
        _put_bytes(buf, engine_type.encode())
        _put_bytes(buf, attest_type.encode())
        _put_bytes(buf, text_payload)
        _put_varint(buf, 1 if stream else 0)
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
    text_payload = b""
    stream = False
    # 6.2 协议扩展（可选字段，缺省为空 = 旧格式请求，向后兼容）。
    # P2/P5：text 载荷与流式标志逐字段探测（尾部缺失容忍）。
    if pos < len(data):
        engine_type, pos = _read_len_bytes(data, pos)
        attest_type, pos = _read_len_bytes(data, pos)
    if pos < len(data):
        text_payload, pos = _read_len_bytes(data, pos)
    if pos < len(data):
        sw, pos = _read_varint(data, pos)
        stream = sw == 1
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
        "text_payload": text_payload,
        "stream": stream,
    }


def verify_request(k_sig: bytes, req: dict) -> bool:
    got = req["signature"]
    want = sign_request(k_sig, req["request_id"], req["timestamp_ns"], req["model"],
                        req["max_new_tokens"], req["nonce"], req["cipher_vectors"],
                        req.get("cipher_text", b""), req.get("text_payload", b""),
                        req.get("stream", False))
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


# ---------- P1a 段① 载荷加密信封（与 protocol/go/envelope.go 逐位一致） ----------
#
# AES-256-GCM 信封：方向子密钥（HKDF 域分离）+ 12 字节确定性 nonce
# （"OTPE" + 8 字节大端计数器）+ AAD（sessionID/方向/计数器/endpoint）。
# wire：varint version | varint suite | byte direction | 8B 大端 counter | len-prefixed ciphertext。
# 注：AES-GCM 依赖 cryptography 库，惰性导入——仅信封功能需要，
# 其余协议函数保持纯标准库可用。

ENVELOPE_VERSION = 1
SUITE_AES_GCM = 1
DIRECTION_C2S = 1  # 客户端（网关 wasm 插件）→ TEE
DIRECTION_S2C = 2  # TEE → 客户端

_NONCE_PREFIX = b"OTPE"
_AAD_PREFIX = b"otpmask/aad/v1"

# 段① 信封绑定的南向端点（AAD endpoint 字段取值；双端常量对齐，不随路由别名漂移）
ENDPOINT_KEY_ISSUE = "/key/issue"
ENDPOINT_INFER = "/v1/infer"

_SUBKEY_INFO = {
    DIRECTION_C2S: b"otpmask/kdf/enc/c2s/v1",
    DIRECTION_S2C: b"otpmask/kdf/enc/s2c/v1",
}


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 extract+expand（与 Go hkdfSHA256 一致）
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        mac = hmac.new(prk, digestmod=hashlib.sha256)
        mac.update(t)
        mac.update(info)
        mac.update(bytes([counter]))
        t = mac.digest()
        out += t
        counter += 1
    return out[:length]


def derive_subkey(k_enc: bytes, direction: int) -> bytes:
    if direction not in _SUBKEY_INFO:
        raise ValueError(f"envelope: 未知方向 {direction}")
    return _hkdf_sha256(k_enc, b"", _SUBKEY_INFO[direction], 32)


def _envelope_nonce(counter: int) -> bytes:
    return _NONCE_PREFIX + struct.pack(">Q", counter)


def envelope_aad(session_id: str, direction: int, counter: int, endpoint: str) -> bytes:
    buf = bytearray(_AAD_PREFIX)
    _put_bytes(buf, session_id.encode())
    buf.append(direction)
    buf.extend(struct.pack(">Q", counter))
    _put_bytes(buf, endpoint.encode())
    return bytes(buf)


def _aesgcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM


def seal_envelope(k_enc: bytes, session_id: str, endpoint: str, direction: int,
                  counter: int, plaintext: bytes) -> bytes:
    # Python 侧密钥零化为 best-effort（bytes 不可变）；生产路径（Go 双端）用后即零化
    subkey = derive_subkey(k_enc, direction)
    ct = _aesgcm()(subkey).encrypt(
        _envelope_nonce(counter), plaintext,
        envelope_aad(session_id, direction, counter, endpoint))
    buf = bytearray()
    _put_varint(buf, ENVELOPE_VERSION)
    _put_varint(buf, SUITE_AES_GCM)
    buf.append(direction)
    buf.extend(struct.pack(">Q", counter))
    _put_bytes(buf, ct)
    return bytes(buf)


def open_envelope(k_enc: bytes, session_id: str, endpoint: str,
                  expect_direction: int, data: bytes) -> tuple[bytes, int]:
    # 返回 (明文, 计数器)；版本/方向/套件/密钥/AAD 任一不匹配即抛错（fail-closed）
    pos = 0
    version, pos = _read_varint(data, pos)
    suite, pos = _read_varint(data, pos)
    if pos >= len(data):
        raise ValueError("envelope: direction 截断")
    direction = data[pos]
    pos += 1
    if pos + 8 > len(data):
        raise ValueError("envelope: counter 截断")
    counter = struct.unpack(">Q", data[pos:pos + 8])[0]
    pos += 8
    ciphertext, pos = _read_len_bytes(data, pos)
    if pos != len(data):
        raise ValueError("envelope: 存在尾部冗余字节")
    if version != ENVELOPE_VERSION:
        raise ValueError(f"envelope: 版本不匹配（got {version} want {ENVELOPE_VERSION}）")
    if direction != expect_direction:
        raise ValueError(f"envelope: 方向不匹配（got {direction} want {expect_direction}）")
    if suite != SUITE_AES_GCM:
        raise ValueError(f"envelope: 未知密码套件 {suite}")
    subkey = derive_subkey(k_enc, expect_direction)
    try:
        pt = _aesgcm()(subkey).decrypt(
            _envelope_nonce(counter), ciphertext,
            envelope_aad(session_id, expect_direction, counter, endpoint))
    except Exception as e:  # InvalidTag 等，统一为 ValueError（与 Go 语义一致）
        raise ValueError(f"envelope: 解密失败（密钥/AAD/密文不匹配）: {e}") from e
    return pt, counter


class CounterWindow:
    """64 槽计数器反重放滑动窗口（决策与 Go CounterWindow 逐例一致）。

    窗口覆盖 [highest-63, highest]：窗口内重复（重放）与落后窗口
    （过期乱序）拒绝，窗口内有界乱序容忍。非线程安全。
    """

    def __init__(self) -> None:
        self._highest = 0
        self._seen = 0  # 位图：bit 63 ↔ highest，bit i ↔ highest-(63-i)
        self._started = False

    def check(self, counter: int) -> None:
        if not self._started:
            self._started = True
            self._highest = counter
            self._seen = 1 << 63
            return
        if counter > self._highest:
            d = counter - self._highest
            self._seen = 0 if d >= 64 else self._seen >> d
            self._highest = counter
            self._seen |= 1 << 63
            return
        if self._highest - counter >= 64:
            raise ValueError(
                f"envelope: 计数器 {counter} 落后窗口（highest={self._highest}），拒绝（重放/过期）")
        bit = 1 << (63 - (self._highest - counter))
        if self._seen & bit:
            raise ValueError(f"envelope: 计数器 {counter} 重复，拒绝（重放）")
        self._seen |= bit


def check_stream_sequence(last: int, got: int) -> None:
    # SSE 流式分片序号：严格递增（got == last+1），跳号/回退/重复一律拒绝
    if got != last + 1:
        raise ValueError(f"envelope: 流序号乱序（last={last} got={got}），拒绝")

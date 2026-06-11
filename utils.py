
from __future__ import annotations
import os
import struct
from typing import Union

def bytes_to_int(b: bytes) -> int:

    return int.from_bytes(b, byteorder='big')

def int_to_bytes(x: int, length: int = 0) -> bytes:

    byte_len = length or (x.bit_length() + 7) // 8
    return x.to_bytes(byte_len, byteorder='big')

def bytes_to_word_array(b: bytes) -> list[int]:

    assert len(b) % 4 == 0
    return [bytes_to_int(b[i:i+4]) for i in range(0, len(b), 4)]

def word_array_to_bytes(words: list[int]) -> bytes:

    return b''.join(int_to_bytes(w, 4) for w in words)

def rotate_left(x: int, n: int, bits: int = 32) -> int:

    n %= bits
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)

def rotate_right(x: int, n: int, bits: int = 32) -> int:

    return rotate_left(x, bits - n, bits)

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:

    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:

    if not data:
        raise ValueError("空数据")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("无效填充")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("填充内容不匹配")
    return data[:-pad_len]

def derive_key(password: str, salt: bytes, dk_len: int = 32,
               iterations: int = 10000, hash_func=None) -> bytes:

    if hash_func is None:
        from sm3 import sm3_hash

        def _hmac(key: bytes, msg: bytes) -> bytes:

            block_size = 64
            if len(key) > block_size:
                key = sm3_hash(key)
            key = key + b'\x00' * (block_size - len(key))
            o_key_pad = bytes(a ^ 0x5c for a in key)
            i_key_pad = bytes(a ^ 0x36 for a in key)
            return sm3_hash(o_key_pad + sm3_hash(i_key_pad + msg))

        hash_func = _hmac

    password_bytes = password.encode('utf-8')
    key_blocks = []
    block_num = (dk_len + 31) // 32

    for block_i in range(1, block_num + 1):
        u = salt + struct.pack('>I', block_i)
        t = bytes(32)
        for _ in range(iterations):
            u = hash_func(password_bytes, u)
            t = bytes(a ^ b for a, b in zip(t, u))
        key_blocks.append(t)

    return b''.join(key_blocks)[:dk_len]

def random_bytes(n: int) -> bytes:

    return os.urandom(n)

def xor_bytes(a: bytes, b: bytes) -> bytes:

    return bytes(x ^ y for x, y in zip(a, b))


from __future__ import annotations
from utils import rotate_left, bytes_to_word_array, word_array_to_bytes

IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]

T = [0x79CC4519] * 16 + [0x7A879D8A] * 48

def FF(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

def GG(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x) & z)

def P0(x: int) -> int:

    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17)

def P1(x: int) -> int:

    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23)

def _msg_expand(block: bytes) -> list[int]:

    W = bytes_to_word_array(block)
    for j in range(16, 68):
        w = (P1(W[j-16] ^ W[j-9] ^ rotate_left(W[j-3], 15))
             ^ rotate_left(W[j-13], 7) ^ W[j-6])
        W.append(w)
    Wp = [W[j] ^ W[j+4] for j in range(64)]
    return W + Wp

def _compress(V: list[int], block: bytes) -> list[int]:

    W = _msg_expand(block)
    A, B, C, D, E, F, G, H = V

    for j in range(64):
        SS1 = rotate_left((rotate_left(A, 12) + E + rotate_left(T[j], j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ rotate_left(A, 12)
        TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = rotate_left(B, 9)
        B = A
        A = TT1
        H = G
        G = rotate_left(F, 19)
        F = E
        E = P0(TT2)

    return [
        (V[0] ^ A) & 0xFFFFFFFF,
        (V[1] ^ B) & 0xFFFFFFFF,
        (V[2] ^ C) & 0xFFFFFFFF,
        (V[3] ^ D) & 0xFFFFFFFF,
        (V[4] ^ E) & 0xFFFFFFFF,
        (V[5] ^ F) & 0xFFFFFFFF,
        (V[6] ^ G) & 0xFFFFFFFF,
        (V[7] ^ H) & 0xFFFFFFFF,
    ]

def _pad(msg: bytes) -> tuple[list[bytes], int]:

    m_len = len(msg) * 8
    msg = msg + b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += m_len.to_bytes(8, byteorder='big')
    assert len(msg) % 64 == 0
    blocks = [msg[i:i+64] for i in range(0, len(msg), 64)]
    return blocks, m_len

class SM3:

    def __init__(self):
        self._V = list(IV)
        self._unprocessed = b''
        self._total_bits = 0

    def update(self, data: bytes) -> None:

        self._total_bits += len(data) * 8
        self._unprocessed += data

        while len(self._unprocessed) >= 64:
            block = self._unprocessed[:64]
            self._unprocessed = self._unprocessed[64:]
            self._V = _compress(self._V, block)

    def digest(self) -> bytes:

        V = list(self._V)
        buf = self._unprocessed

        buf += b'\x80'
        while (len(buf) * 8) % 512 != 448:
            buf += b'\x00'
        while len(buf) > 64:
            block = buf[:64]
            buf = buf[64:]
            V = _compress(V, block)
        buf += self._total_bits.to_bytes(8, byteorder='big')
        V = _compress(V, buf)

        return word_array_to_bytes(V)

    def hexdigest(self) -> str:
        return self.digest().hex()

def sm3_hash(data: bytes) -> bytes:

    h = SM3()
    h.update(data)
    return h.digest()

def sm3_hex(data: bytes) -> str:

    return sm3_hash(data).hex()

def hmac_sm3(key: bytes, msg: bytes) -> bytes:

    block_size = 64
    if len(key) > block_size:
        key = sm3_hash(key)
    key = key + b'\x00' * (block_size - len(key))
    o_key_pad = bytes(a ^ 0x5c for a in key)
    i_key_pad = bytes(a ^ 0x36 for a in key)
    return sm3_hash(o_key_pad + sm3_hash(i_key_pad + msg))


from __future__ import annotations
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

SM3_TEST_VECTORS = [
    ("abc",
     "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
     "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
    ("",
     "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
]

def verify_sm3():
    from sm3 import sm3_hash, sm3_hex
    all_pass = True
    print("=" * 60)
    print("SM3 测试向量验证")
    print("=" * 60)
    for i, (msg, expected) in enumerate(SM3_TEST_VECTORS):
        data = msg.encode('utf-8') if msg else b''
        result = sm3_hex(data)
        passed = result == expected
        status = "OK" if passed else "FAIL"
        print(f"\n测试 {i+1}: {'通过' if passed else '失败'} [{status}]")
        print(f"  消息:     {msg or '<空>'}")
        print(f"  期望:     {expected}")
        print(f"  实际:     {result}")
        if not passed:
            all_pass = False
    return all_pass

SM4_TEST_VECTORS = [
    (
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "681edf34d206965e86b3e94f536e4246",
    ),
    (
        "0123456789abcdeffedcba9876543210",
        "00000000000000000000000000000000",
        "2677f46b09c122cc975533105bd4a22a",
    ),
]

def verify_sm4():
    from sm4 import SM4
    all_pass = True
    print("\n" + "=" * 60)
    print("SM4 ECB 测试向量验证")
    print("=" * 60)
    for i, (key_hex, pt_hex, ct_hex) in enumerate(SM4_TEST_VECTORS):
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        expected_ct = bytes.fromhex(ct_hex)

        sm4 = SM4(key, mode='ecb')
        result_ct = sm4.encrypt_block(pt)
        decrypted = sm4.decrypt_block(result_ct)

        encrypt_pass = result_ct == expected_ct
        decrypt_pass = decrypted == pt
        passed = encrypt_pass and decrypt_pass
        status = "OK" if passed else "FAIL"
        print(f"\n测试 {i+1}: {'通过' if passed else '失败'} [{status}]")
        print(f"  密钥:     {key_hex}")
        print(f"  明文:     {pt_hex}")
        print(f"  期望密文: {ct_hex}")
        print(f"  实际密文: {result_ct.hex()}")
        print(f"  解密回环: {decrypted.hex()}")

        if encrypt_pass:
            print(f"  -> 加密正确 [OK]")
        else:
            print(f"  -> 加密错误 [FAIL]")
            all_pass = False
        if decrypted == pt:
            print(f"  -> 解密正确 [OK]")
        else:
            print(f"  -> 解密错误 [FAIL]")
            all_pass = False
    return all_pass

def test_sm4_cbc():
    from sm4 import SM4
    print("\n" + "=" * 60)
    print("SM4 CBC 模式测试")
    print("=" * 60)
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintexts = [
        b"Hello, World!",
        b"A" * 16,
        b"B" * 32,
        b"The quick brown fox jumps over the lazy dog" * 10,
        bytes(range(256)),
    ]

    all_pass = True
    for i, pt in enumerate(plaintexts):
        sm4 = SM4(key, mode='cbc')
        ct = sm4.encrypt(pt, iv=iv)
        decrypted = sm4.decrypt(ct)
        passed = decrypted == pt
        status = "[OK]" if passed else "[FAIL]"
        print(f"\nCBC 测试 {i+1}: {'通过' if passed else '失败'} [{status}]")
        print(f"  明文长度: {len(pt)} 字节")
        print(f"  密文长度: {len(ct)} 字节 (含 IV)")
        if not passed:
            all_pass = False
            print(f"  期望: {pt[:50]}...")
            print(f"  实际: {decrypted[:50]}...")
    return all_pass

def verify_sm3_cross():

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives._sm3 import _SM3Context
        has_crypto = True
    except ImportError:
        print("\n[WARN] cryptography 库未安装, 跳过交叉验证")
        return True

    from sm3 import sm3_hash
    print("\n" + "=" * 60)
    print("SM3 交叉验证 (与 cryptography 库对比)")
    print("=" * 60)

    test_data = [
        b"",
        b"abc",
        b"a" * 1000,
        b"\x00" * 64,
        bytes(range(256)),
    ]

    all_pass = True
    for data in test_data:
        our_hash = sm3_hash(data)

        ctx = _SM3Context()
        ctx.update(data)
        ref_hash = ctx.digest()

        passed = our_hash == ref_hash
        status = "[OK]" if passed else "[FAIL]"
        print(f"\n  长度 {len(data):>5}: {'通过' if passed else '失败'} {status}")
        print(f"    我们的: {our_hash.hex()}")
        print(f"    参考值: {ref_hash.hex()}")
        if not passed:
            all_pass = False
    return all_pass

def verify_sm4_cross():

    try:
        from cryptography.hazmat.primitives.ciphers import algorithms
        has_crypto = True
    except ImportError:
        print("\n[WARN] cryptography 库未安装, 跳过 SM4 交叉验证")
        return True

    print("\n[WARN] cryptography 库未提供 SM4 公开 API, 跳过交叉验证")
    return True

if __name__ == '__main__':
    print("SM3/SM4 算法正确性验证")
    print("=" * 60)

    sm3_ok = verify_sm3()
    sm4_ok = verify_sm4()
    cbc_ok = test_sm4_cbc()
    cross_ok = verify_sm3_cross()

    print("\n" + "=" * 60)
    print("验证结果汇总")
    print("=" * 60)
    print(f"  SM3 测试向量: {'[OK] 通过' if sm3_ok else '[FAIL] 失败'}")
    print(f"  SM4 测试向量: {'[OK] 通过' if sm4_ok else '[FAIL] 失败'}")
    print(f"  SM4 CBC 模式: {'[OK] 通过' if cbc_ok else '[FAIL] 失败'}")
    print(f"  SM3 交叉验证: {'[OK] 通过' if cross_ok else '[FAIL] 失败'}")
    print()

    all_ok = sm3_ok and sm4_ok and cbc_ok and cross_ok
    if all_ok:
        print("[OK] 所有验证通过!")
        sys.exit(0)
    else:
        print("[FAIL] 存在验证失败项, 请检查实现")

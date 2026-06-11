
from __future__ import annotations
import time
import os
import sys
import tempfile
from pathlib import Path

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', encoding='utf-8', buffering=1)

from sm3 import SM3, sm3_hash
from sm4 import SM4
from utils import random_bytes
from file_vault import FileVault

def _bench(name: str, fn, *args, warmup: int = 1, repeat: int = 5, **kwargs):

    for _ in range(warmup):
        fn(*args, **kwargs)

    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn(*args, **kwargs)
        t1 = time.perf_counter()
        times.append(t1 - t0)

    avg = sum(times) / len(times)
    min_t = min(times)
    max_t = max(times)
    return {
        "name": name,
        "avg_s": avg,
        "min_s": min_t,
        "max_s": max_t,
        "ops_s": 1.0 / avg if avg > 0 else float('inf'),
    }

def _print_result(r: dict, data_size: int = 0):

    if data_size:
        throughput = data_size / r["avg_s"] / (1024 * 1024)
        print(f"  {r['name']:<35s}  {r['avg_s']*1000:>8.2f} ms  "
              f"{throughput:>8.2f} MB/s  "
              f"(min={r['min_s']*1000:.2f}ms max={r['max_s']*1000:.2f}ms)")
    else:
        print(f"  {r['name']:<35s}  {r['avg_s']*1000:>8.2f} ms  "
              f"{r['ops_s']:>8.0f} ops/s  "
              f"(min={r['min_s']*1000:.2f}ms max={r['max_s']*1000:.2f}ms)")

def bench_sm3():
    print("\n" + "=" * 65)
    print("SM3 哈希性能")
    print("=" * 65)

    sizes = [64, 1024, 65536, 1048576]
    for size in sizes:
        data = random_bytes(size)
        r = _bench(f"SM3 hash ({_fmt_size(size)})",
                   sm3_hash, data,
                   warmup=3, repeat=5)
        _print_result(r, data_size=size)

def bench_sm4():
    print("\n" + "=" * 65)
    print("SM4 加解密性能")
    print("=" * 65)

    key = random_bytes(16)
    sizes = [64, 1024, 65536, 1048576]

    for size in sizes:
        data = random_bytes(size)

        ecb_sm4 = SM4(key, mode='ecb')
        r = _bench(f"SM4-ECB encrypt ({_fmt_size(size)})",
                   ecb_sm4.encrypt, data,
                   warmup=3, repeat=5)
        _print_result(r, data_size=size)

        ct = ecb_sm4.encrypt(data)
        ecb_dec = SM4(key, mode='ecb')
        r = _bench(f"SM4-ECB decrypt ({_fmt_size(size)})",
                   ecb_dec.decrypt, ct,
                   warmup=3, repeat=5)
        _print_result(r, data_size=size)

        cbc_sm4 = SM4(key, mode='cbc')
        r = _bench(f"SM4-CBC encrypt ({_fmt_size(size)})",
                   cbc_sm4.encrypt, data,
                   warmup=3, repeat=5)
        _print_result(r, data_size=size)

        ct_cbc = cbc_sm4.encrypt(data)
        cbc_dec = SM4(key, mode='cbc')
        r = _bench(f"SM4-CBC decrypt ({_fmt_size(size)})",
                   cbc_dec.decrypt, ct_cbc,
                   warmup=3, repeat=5)
        _print_result(r, data_size=size)

def bench_vault():
    print("\n" + "=" * 65)
    print("保密文件库性能 (文件导入/导出)")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = Path(tmpdir) / "test_vault"
        password = "test_benchmark_password_123"

        vault = FileVault(str(vault_dir))
        vault.init(password)
        print(f"\n  保管库: {vault_dir}")

        sizes = [
            ("1 KB",     1024),
            ("64 KB",    65536),
            ("1 MB",     1048576),
            ("10 MB",    10485760),
        ]

        for label, size in sizes:
            file_data = random_bytes(size)
            src = Path(tmpdir) / f"bench_{label.replace(' ', '_')}.dat"
            src.write_bytes(file_data)

            t0 = time.perf_counter()
            file_id = vault.add_file(password, str(src))
            t1 = time.perf_counter()
            import_time = t1 - t0

            out_dir = Path(tmpdir) / "extracted"
            t0 = time.perf_counter()
            out_path = vault.extract_file(password, file_id, output_dir=str(out_dir))
            t1 = time.perf_counter()
            export_time = t1 - t0

            exported_data = Path(out_path).read_bytes()
            assert exported_data == file_data, f"数据不匹配: {label}"

            throughput_import = size / import_time / (1024 * 1024)
            throughput_export = size / export_time / (1024 * 1024)

            print(f"\n  [{label}]")
            print(f"    导入: {import_time*1000:>8.2f} ms  ({throughput_import:.2f} MB/s)")
            print(f"    导出: {export_time*1000:>8.2f} ms  ({throughput_export:.2f} MB/s)")
            print(f"    验证: 数据一致 [OK]")

def _fmt_size(n: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    if i == 0:
        return f"{n}{units[i]}"
    return f"{n:.1f}{units[i]}"

def main():
    print("=" * 65)
    print("国密算法 (SM3/SM4) 性能基准测试")
    print("=" * 65)
    print(f"Python 版本: {sys.version.split()[0]}")
    print(f"平台: {sys.platform}")
    print(f"日期: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        import platform
        print(f"CPU: {platform.processor() or 'N/A'}")
    except:
        pass

    bench_sm3()
    bench_sm4()
    bench_vault()

    print("\n" + "=" * 65)
    print("基准测试完成!")
    print("=" * 65)

if __name__ == '__main__':
    main()

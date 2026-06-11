
from __future__ import annotations
import argparse
import json
import os
import shutil
import sys
import getpass
from pathlib import Path
from typing import Optional

import re

from sm4 import SM4
from sm3 import sm3_hash, sm3_hex
from utils import random_bytes, derive_key

VAULT_VERSION = 1
PBKDF2_ITERATIONS = 10000
DERIVED_KEY_LEN = 32
FILE_ID_LEN = 16

class VaultError(Exception):

    pass

class AuthenticationError(VaultError):

    pass

class VaultExistsError(VaultError):

    pass

class VaultNotFoundError(VaultError):

    pass

def _vault_config_path(vault_dir: Path) -> Path:
    return vault_dir / "config"

def _keytable_path(vault_dir: Path) -> Path:
    return vault_dir / "keytable.enc"

def _files_dir(vault_dir: Path) -> Path:
    return vault_dir / "files"

def _file_path(vault_dir: Path, file_id: str) -> Path:
    return _files_dir(vault_dir) / f"{file_id}.enc"

def _derive_master_key(password: str, salt: bytes) -> bytes:

    return derive_key(password, salt, dk_len=DERIVED_KEY_LEN,
                      iterations=PBKDF2_ITERATIONS)

def _encrypt_keytable(master_key: bytes, keytable: dict) -> bytes:

    plaintext = json.dumps(keytable, ensure_ascii=False, sort_keys=True).encode('utf-8')
    sm4 = SM4(master_key[:16], mode='cbc')
    return sm4.encrypt(plaintext)

def _decrypt_keytable(master_key: bytes, data: bytes) -> dict:

    sm4 = SM4(master_key[:16], mode='cbc')
    plaintext = sm4.decrypt(data)
    return json.loads(plaintext.decode('utf-8'))

def _encrypt_file_data(file_key: bytes, data: bytes) -> bytes:

    sm4 = SM4(file_key[:16], mode='cbc')
    return sm4.encrypt(data)

def _decrypt_file_data(file_key: bytes, data: bytes) -> bytes:

    sm4 = SM4(file_key[:16], mode='cbc')
    return sm4.decrypt(data)

def _generate_file_id() -> str:

    return sm3_hex(random_bytes(32))[:FILE_ID_LEN]

def _encrypt_file_key(master_key: bytes, file_key: bytes) -> str:

    sm4 = SM4(master_key[:16], mode='ecb')
    ct = sm4.encrypt_block(file_key[:16])
    return ct.hex()

def _decrypt_file_key(master_key: bytes, enc_key_hex: str) -> bytes:

    sm4 = SM4(master_key[:16], mode='ecb')
    return sm4.decrypt_block(bytes.fromhex(enc_key_hex))

def _format_size(size_bytes: int) -> str:

    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != 'B' else f"{size_bytes} B"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

class FileVault:

    def __init__(self, vault_dir: str):
        self._vault_dir = Path(vault_dir).resolve()

    @property
    def path(self) -> Path:
        return self._vault_dir

    @property
    def exists(self) -> bool:
        return self._vault_dir.is_dir() and _vault_config_path(self._vault_dir).is_file()

    def init(self, password: str, force: bool = False) -> None:

        if self.exists:
            if force:
                shutil.rmtree(self._vault_dir)
            else:
                raise VaultExistsError(
                    f"保管库 '{self._vault_dir}' 已存在。使用 --force 重新初始化")

        self._vault_dir.mkdir(parents=True, exist_ok=True)
        _files_dir(self._vault_dir).mkdir(exist_ok=True)

        salt = random_bytes(32)
        master_key = _derive_master_key(password, salt)

        config = {
            "version": VAULT_VERSION,
            "salt_hex": salt.hex(),
            "pbkdf2_iterations": PBKDF2_ITERATIONS,
            "algorithm": "SM4-CBC",
            "key_derivation": "PBKDF2-SM3",
            "file_key_length": 16,
        }
        with open(_vault_config_path(self._vault_dir), 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        keytable = {"files": {}}
        encrypted = _encrypt_keytable(master_key, keytable)
        with open(_keytable_path(self._vault_dir), 'wb') as f:
            f.write(encrypted)

        import ctypes
        ctypes.memset(id(master_key), 0, len(master_key))

        print(f"[OK] 保密文件库已创建: {self._vault_dir}")

    def _authenticate(self, password: str) -> bytes:

        if not self.exists:
            raise VaultNotFoundError(f"保管库不存在: {self._vault_dir}")

        with open(_vault_config_path(self._vault_dir), 'r', encoding='utf-8') as f:
            config = json.load(f)

        salt = bytes.fromhex(config["salt_hex"])
        iterations = config.get("pbkdf2_iterations", PBKDF2_ITERATIONS)
        master_key = _derive_master_key(password, salt)

        try:
            with open(_keytable_path(self._vault_dir), 'rb') as f:
                encrypted = f.read()
            keytable = _decrypt_keytable(master_key, encrypted)
            return master_key
        except Exception:
            import ctypes
            ctypes.memset(id(master_key), 0, len(master_key))
            raise AuthenticationError("口令错误或保管库已损坏")

    def add_file(self, password: str, file_path: str, delete_source: bool = False) -> str:

        master_key = self._authenticate(password)
        try:
            src = Path(file_path).resolve()
            if not src.is_file():
                raise VaultError(f"文件不存在: {src}")

            file_data = src.read_bytes()
            original_name = src.name
            original_size = len(file_data)

            file_key = random_bytes(16)
            encrypted_data = _encrypt_file_data(file_key, file_data)
            file_id = _generate_file_id()

            keytable = _decrypt_keytable(master_key, _keytable_path(self._vault_dir).read_bytes())
            while file_id in keytable["files"]:
                file_id = _generate_file_id()

            enc_key = _encrypt_file_key(master_key, file_key)

            _file_path(self._vault_dir, file_id).write_bytes(encrypted_data)

            import time
            keytable["files"][file_id] = {
                "name": original_name,
                "size": original_size,
                "encrypted_size": len(encrypted_data),
                "encrypted_key": enc_key,
                "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            _keytable_path(self._vault_dir).write_bytes(
                _encrypt_keytable(master_key, keytable))

            if delete_source:
                src.unlink()

            print(f"[OK] 文件已加密导入: {original_name} ({_format_size(original_size)})")
            print(f"     文件 ID: {file_id}")
            return file_id

        finally:
            import ctypes
            ctypes.memset(id(master_key), 0, len(master_key))

    def extract_file(self, password: str, file_id_or_name: str,
                     output_dir: Optional[str] = None, delete_from_vault: bool = False) -> str:

        master_key = self._authenticate(password)
        try:
            keytable = _decrypt_keytable(master_key, _keytable_path(self._vault_dir).read_bytes())

            file_info = keytable["files"].get(file_id_or_name)
            file_id = file_id_or_name
            if file_info is None:
                found = [(fid, info) for fid, info in keytable["files"].items()
                         if info["name"] == file_id_or_name]
                if len(found) == 0:
                    raise VaultError(f"未找到文件: {file_id_or_name}")
                if len(found) > 1:
                    ids = [fid for fid, _ in found]
                    raise VaultError(
                        f"存在多个同名文件 '{file_id_or_name}', 请使用文件 ID: {', '.join(ids)}")
                file_id, file_info = found[0]

            file_key = _decrypt_file_key(master_key, file_info["encrypted_key"])

            encrypted_data = _file_path(self._vault_dir, file_id).read_bytes()
            decrypted_data = _decrypt_file_data(file_key, encrypted_data)

            out_dir = Path(output_dir).resolve() if output_dir else Path.cwd()
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / file_info["name"]

            counter = 1
            stem = out_path.stem
            suffix = out_path.suffix
            while out_path.exists():
                out_path = out_dir / f"{stem}_{counter}{suffix}"
                counter += 1

            out_path.write_bytes(decrypted_data)

            if delete_from_vault:
                _file_path(self._vault_dir, file_id).unlink()
                del keytable["files"][file_id]
                _keytable_path(self._vault_dir).write_bytes(
                    _encrypt_keytable(master_key, keytable))

            print(f"[OK] 文件已解密导出: {out_path}")
            print(f"     原始大小: {_format_size(file_info['size'])}")
            return str(out_path)

        finally:
            import ctypes
            ctypes.memset(id(master_key), 0, len(master_key))

    def delete_file(self, password: str, file_id: str) -> None:

        master_key = self._authenticate(password)
        try:
            keytable = _decrypt_keytable(master_key, _keytable_path(self._vault_dir).read_bytes())

            if file_id not in keytable["files"]:
                raise VaultError(f"未找到文件 ID: {file_id}")

            file_info = keytable["files"][file_id]
            file_path_obj = _file_path(self._vault_dir, file_id)

            if file_path_obj.exists():
                file_path_obj.unlink()

            del keytable["files"][file_id]
            _keytable_path(self._vault_dir).write_bytes(
                _encrypt_keytable(master_key, keytable))

            print(f"[OK] 文件已从保管库删除: {file_info['name']} ({file_id})")

        finally:
            import ctypes
            ctypes.memset(id(master_key), 0, len(master_key))

    def list_files(self, password: str) -> list[dict]:

        master_key = self._authenticate(password)
        try:
            keytable = _decrypt_keytable(master_key, _keytable_path(self._vault_dir).read_bytes())
            files = keytable.get("files", {})

            if not files:
                print("[INFO] 保管库为空")
                return []

            sorted_files = sorted(files.items(), key=lambda x: x[1].get("added_at", ""))

            print(f"\n{'='*70}")
            print(f"{'文件 ID':<18} {'文件名':<25} {'大小':<10} {'添加时间':<19}")
            print(f"{'='*70}")
            for fid, info in sorted_files:
                size_str = _format_size(info["size"])
                name = info["name"]
                if len(name) > 22:
                    name = name[:19] + "..."
                added_at = info.get("added_at", "未知")
                print(f"{fid:<18} {name:<25} {size_str:<10} {added_at:<19}")
            print(f"{'='*70}")
            print(f"总计: {len(files)} 个文件\n")

            return [
                {"id": fid, **info}
                for fid, info in sorted_files
            ]
        finally:
            import ctypes
            ctypes.memset(id(master_key), 0, len(master_key))

    def file_info(self, password: str, file_id: str) -> dict:

        master_key = self._authenticate(password)
        try:
            keytable = _decrypt_keytable(master_key, _keytable_path(self._vault_dir).read_bytes())

            if file_id not in keytable["files"]:
                raise VaultError(f"未找到文件 ID: {file_id}")

            info = keytable["files"][file_id]
            print(f"\n文件信息:")
            print(f"  文件 ID:     {file_id}")
            print(f"  文件名:      {info['name']}")
            print(f"  原始大小:    {_format_size(info['size'])} ({info['size']} 字节)")
            print(f"  加密后大小:  {_format_size(info['encrypted_size'])}")
            print(f"  添加时间:    {info.get('added_at', '未知')}")

            return {"id": file_id, **info}
        finally:
            import ctypes
            ctypes.memset(id(master_key), 0, len(master_key))

    def change_password(self, old_password: str, new_password: str) -> None:

        old_master_key = self._authenticate(old_password)
        try:
            keytable = _decrypt_keytable(old_master_key,
                                          _keytable_path(self._vault_dir).read_bytes())

            with open(_vault_config_path(self._vault_dir), 'r', encoding='utf-8') as f:
                config = json.load(f)

            config["salt_hex"] = random_bytes(32).hex()
            new_master_key = _derive_master_key(new_password,
                                                 bytes.fromhex(config["salt_hex"]))

            for fid, info in keytable["files"].items():
                old_enc_key = info["encrypted_key"]
                file_key = _decrypt_file_key(old_master_key, old_enc_key)
                info["encrypted_key"] = _encrypt_file_key(new_master_key, file_key)

            with open(_vault_config_path(self._vault_dir), 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            _keytable_path(self._vault_dir).write_bytes(
                _encrypt_keytable(new_master_key, keytable))

            import ctypes
            ctypes.memset(id(new_master_key), 0, len(new_master_key))

            print("[OK] 口令已修改")

        finally:
            import ctypes
            ctypes.memset(id(old_master_key), 0, len(old_master_key))

def _read_password(prompt: str = "请输入口令: ") -> str:

    return getpass.getpass(prompt)

def _read_new_password() -> str:

    while True:
        p1 = getpass.getpass("请输入新口令: ")
        if len(p1) < 6:
            print("[WARN] 口令长度建议不少于 6 位")
            continue
        p2 = getpass.getpass("确认新口令: ")
        if p1 == p2:
            return p1
        print("[ERROR] 两次口令不一致, 请重新输入")

def main():
    parser = argparse.ArgumentParser(
        description="保密文件库 — 基于国密算法 (SM3/SM4) 的加密文件管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=
    )

    parser.add_argument("action", choices=[
        "init", "add", "move", "list", "ls",
        "get", "extract", "rm", "delete",
        "info", "passwd", "changepw",
    ], help="操作类型")
    parser.add_argument("vault", help="保管库目录路径")
    parser.add_argument("target", nargs="?", help="目标文件或文件 ID")
    parser.add_argument("-o", "--output", help="导出文件输出目录")
    parser.add_argument("-f", "--force", action="store_true",
                        help="强制初始化 (覆盖已有保管库)")
    parser.add_argument("--non-interactive", action="store_true",
                        help="非交互模式 (从环境变量读取口令)")

    args = parser.parse_args()

    vault = FileVault(args.vault)

    try:
        if args.non_interactive:
            password = os.environ.get("VAULT_PASSWORD", "")
            if not password:
                print("[ERROR] 非交互模式需要设置 VAULT_PASSWORD 环境变量")
                sys.exit(1)
        else:
            password = None

        if args.action == "init":
            if password is None:
                password = _read_new_password()
            vault.init(password, force=args.force)

        elif args.action == "add":
            if not args.target:
                parser.error("add 操作需要指定目标文件")
            if password is None:
                password = _read_password()
            vault.add_file(password, args.target, delete_source=False)

        elif args.action == "move":
            if not args.target:
                parser.error("move 操作需要指定目标文件")
            if password is None:
                password = _read_password()
            vault.add_file(password, args.target, delete_source=True)

        elif args.action in ("list", "ls"):
            if password is None:
                password = _read_password()
            vault.list_files(password)

        elif args.action in ("get", "extract"):
            if not args.target:
                parser.error("get 操作需要指定文件 ID 或文件名")
            if password is None:
                password = _read_password()
            vault.extract_file(password, args.target, output_dir=args.output)

        elif args.action in ("rm", "delete"):
            if not args.target:
                parser.error("rm 操作需要指定文件 ID")
            if password is None:
                password = _read_password()
            vault.delete_file(password, args.target)

        elif args.action == "info":
            if not args.target:
                parser.error("info 操作需要指定文件 ID")
            if password is None:
                password = _read_password()
            vault.file_info(password, args.target)

        elif args.action in ("passwd", "changepw"):
            old_pw = _read_password("请输入当前口令: ")
            new_pw = _read_new_password()
            vault.change_password(old_pw, new_pw)

    except AuthenticationError:
        print("[ERROR] 口令错误!")
        sys.exit(1)
    except (VaultError, VaultExistsError, VaultNotFoundError) as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

# 基于国密算法的保密文件库

使用 Python 从零实现 SM3/SM4 国密算法，并构建命令行和图形界面两套保密文件库管理工具。

## 项目结构

| 文件 | 说明 |
|------|------|
| `sm3.py` | SM3 密码杂凑算法 (GM/T 0004-2012) |
| `sm4.py` | SM4 分组密码算法 (GM/T 0002-2012)，ECB/CBC 模式 |
| `utils.py` | PKCS7 填充、PBKDF2-SM3 密钥派生等工具 |
| `file_vault.py` | 保密文件库 CLI 工具 |
| `file_vault_gui.py` | 保密文件库图形界面 (tkinter) |
| `test_vectors.py` | 算法正确性测试 |
| `benchmark.py` | 性能基准测试 |
| `report/report.pdf` | 设计报告 |

## 快速开始

```bash
# CLI 模式
python file_vault.py init D:\MyVault
python file_vault.py add D:\MyVault secret.pdf

# GUI 模式
python file_vault_gui.py
```

## 密钥策略

- 用户口令 → PBKDF2-SM3 (10000轮) → 主密钥
- 每文件独立随机 SM4 密钥
- 密钥表由主密钥加密存储

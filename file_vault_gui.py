
from __future__ import annotations
import ctypes
import os
import sys
import threading
import tempfile
from pathlib import Path
from tkinter import (
    Tk, Toplevel, ttk, StringVar, scrolledtext,
    filedialog, messagebox, font as tkfont,
    Menu as tkMenu, Listbox,
)
from typing import Optional

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

def _get_dpi_scale() -> float:

    try:
        dc = ctypes.windll.user32.GetDC(0)
        dpi = ctypes.windll.gdi32.GetDeviceCaps(dc, 88)
        ctypes.windll.user32.ReleaseDC(0, dc)
        return dpi / 96.0
    except Exception:
        return 1.0

_DPI_SCALE = max(_get_dpi_scale(), 1.0)
_SF = lambda pt: ("微软雅黑", max(round(pt * _DPI_SCALE), pt))
_SFB = lambda pt: ("微软雅黑", max(round(pt * _DPI_SCALE), pt), "bold")
_SFM = lambda pt: ("Microsoft YaHei UI", max(round(pt * _DPI_SCALE), pt))
_SFC = lambda pt: ("Consolas", max(round(pt * _DPI_SCALE), pt))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from file_vault import FileVault, AuthenticationError, VaultError

class PasswordDialog(Toplevel):

    def __init__(self, parent: Tk, title: str = "请输入口令",
                 confirm: bool = False, old_pw: bool = False):
        super().__init__(parent)
        self.result: Optional[str] = None
        self.confirm = confirm
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.geometry("+%d+%d" % (parent.winfo_x() + 100, parent.winfo_y() + 150))
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="当前口令:" if old_pw else "请输入口令:",
                  font=_SF(8)).pack(anchor="w")

        self.pw_var = StringVar()
        self.pw_entry = ttk.Entry(frame, textvariable=self.pw_var,
                                  show="*", width=30, font=_SF(8))
        self.pw_entry.pack(fill="x", pady=(5, 10))
        self.pw_entry.focus_set()

        self.pw2_var = StringVar()
        self.pw2_label = ttk.Label(frame, text="确认口令:",
                                   font=_SF(8))
        self.pw2_entry = ttk.Entry(frame, textvariable=self.pw2_var,
                                   show="*", width=30, font=_SF(8))

        if confirm:
            self.pw2_label.pack(anchor="w")
            self.pw2_entry.pack(fill="x", pady=(0, 10))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(10, 0))

        ttk.Button(btn_frame, text="确定", width=10,
                   command=self._on_ok).pack(side="right", padx=(10, 0))
        ttk.Button(btn_frame, text="取消", width=10,
                   command=self._on_cancel).pack(side="right")

        self.bind("<Return>", lambda e: self._on_ok())
        self.bind("<Escape>", lambda e: self._on_cancel())
        self.wait_window()

    def _on_ok(self):
        pw1 = self.pw_var.get()
        if self.confirm:
            pw2 = self.pw2_var.get()
            if len(pw1) < 4:
                messagebox.showwarning("提示", "口令长度不少于 4 位", parent=self)
                return
            if pw1 != pw2:
                messagebox.showerror("错误", "两次口令不一致", parent=self)
                return
        self.result = pw1
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

class FileInfoDialog(Toplevel):

    def __init__(self, parent: Tk, info: dict):
        super().__init__(parent)
        self.title("文件信息 - " + info.get("name", ""))
        self.transient(parent)
        self.grab_set()
        self.geometry("+%d+%d" % (parent.winfo_x() + 150, parent.winfo_y() + 180))
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)

        fields = [
            ("文件 ID", info.get("id", "")),
            ("文件名", info.get("name", "")),
            ("原始大小", _fmt_size(info.get("size", 0))),
            ("加密后大小", _fmt_size(info.get("encrypted_size", 0))),
            ("添加时间", info.get("added_at", "")),
        ]
        for i, (label, value) in enumerate(fields):
            ttk.Label(frame, text=label + ":", font=_SFB(8)).grid(
                row=i, column=0, sticky="w", pady=3, padx=(0, 10))
            ttk.Label(frame, text=value, font=_SF(8)).grid(
                row=i, column=1, sticky="w", pady=3)

        ttk.Button(frame, text="关闭", width=10,
                   command=self.destroy).grid(row=len(fields), column=0,
                                               columnspan=2, pady=(15, 0))

_RECENT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "file_vault_recent.json")
_MAX_RECENT = 8

def _load_recent() -> list[str]:

    try:
        import json
        with open(_RECENT_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("recent", [])[:_MAX_RECENT]
    except Exception:
        return []

def _save_recent(paths: list[str]):

    try:
        import json
        with open(_RECENT_FILE, 'w', encoding='utf-8') as f:
            json.dump({"recent": paths[:_MAX_RECENT]}, f,
                      ensure_ascii=False, indent=2)
    except Exception:
        pass

def _add_recent(path: str):

    paths = _load_recent()
    if path in paths:
        paths.remove(path)
    paths.insert(0, path)
    _save_recent(paths)

class FileVaultGUI:

    def __init__(self):
        self.root = Tk()
        self.root.title("保密文件库 — 基于国密算法 (SM3/SM4)")

        base_w, base_h = 960, 640
        sw = int(base_w * _DPI_SCALE)
        sh = int(base_h * _DPI_SCALE)
        self.root.geometry(f"{sw}x{sh}")
        self.root.minsize(int(800 * _DPI_SCALE), int(520 * _DPI_SCALE))

        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            try:
                style.theme_use("winnative")
            except Exception:
                pass
        default_font = _SF(8)
        style.configure(".", font=default_font)
        style.configure("Treeview", font=_SF(8),
                        rowheight=max(22, int(22 * _DPI_SCALE)))
        style.configure("Treeview.Heading", font=_SFB(8))

        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self._vault: Optional[FileVault] = None
        self._password: Optional[str] = None

        self._build_menu()
        self._build_ui()
        self._center_window()
        self._update_recent_menu()
        self._update_ui_state()

    def _build_menu(self):

        menubar = tkMenu(self.root)

        vault_menu = tkMenu(menubar, tearoff=0)
        vault_menu.add_command(label="初始化保管库...", command=self._on_init_vault,
                               accelerator="Ctrl+N")
        vault_menu.add_command(label="打开保管库...", command=self._on_open_vault,
                               accelerator="Ctrl+O")

        self._recent_menu = tkMenu(menubar, tearoff=0)
        vault_menu.add_cascade(label="最近使用的保管库", menu=self._recent_menu)
        vault_menu.add_command(label="管理最近保管库...", command=self._manage_recent)

        vault_menu.add_separator()
        vault_menu.add_command(label="退出", command=self.root.quit,
                               accelerator="Alt+F4")
        menubar.add_cascade(label="保管库(V)", menu=vault_menu)

        op_menu = tkMenu(menubar, tearoff=0)
        op_menu.add_command(label="添加文件...", command=self._on_add_file,
                            accelerator="Ctrl+A")
        op_menu.add_command(label="移入文件...", command=self._on_move_file,
                            accelerator="Ctrl+M")
        op_menu.add_command(label="导出文件...", command=self._on_extract_file,
                            accelerator="Ctrl+E")
        op_menu.add_command(label="删除文件", command=self._on_delete_file,
                            accelerator="Del")
        op_menu.add_command(label="查看文件信息", command=self._on_show_info,
                            accelerator="Ctrl+I")
        op_menu.add_separator()
        op_menu.add_command(label="修改口令...", command=self._on_change_password,
                            accelerator="Ctrl+P")
        menubar.add_cascade(label="操作(O)", menu=op_menu)

        view_menu = tkMenu(menubar, tearoff=0)
        view_menu.add_command(label="刷新文件列表", command=self._on_refresh,
                              accelerator="F5")
        view_menu.add_separator()
        view_menu.add_command(label="显示日志", command=self._toggle_log,
                              accelerator="Ctrl+L")
        self._view_menu = view_menu
        menubar.add_cascade(label="查看(V)", menu=view_menu)

        help_menu = tkMenu(menubar, tearoff=0)
        help_menu.add_command(label="使用说明", command=self._show_help)
        help_menu.add_separator()
        help_menu.add_command(label="关于保密文件库", command=self._show_about)
        menubar.add_cascade(label="帮助(H)", menu=help_menu)

        self.root.config(menu=menubar)

        self.root.bind("<Control-n>", lambda e: self._on_init_vault())
        self.root.bind("<Control-o>", lambda e: self._on_open_vault())
        self.root.bind("<Control-a>", lambda e: self._on_add_file())
        self.root.bind("<Control-m>", lambda e: self._on_move_file())
        self.root.bind("<Control-e>", lambda e: self._on_extract_file())
        self.root.bind("<Delete>", lambda e: self._on_delete_file())
        self.root.bind("<Control-i>", lambda e: self._on_show_info())
        self.root.bind("<Control-p>", lambda e: self._on_change_password())
        self.root.bind("<F5>", lambda e: self._on_refresh())
        self.root.bind("<Control-l>", lambda e: self._toggle_log())

    def _update_recent_menu(self):

        self._recent_menu.delete(0, "end")
        paths = _load_recent()
        if not paths:
            self._recent_menu.add_command(label="(无)", state="disabled")
        else:
            for i, p in enumerate(paths[:8], 1):
                label = f"{i}. {p}"
                self._recent_menu.add_command(
                    label=label,
                    command=lambda p=p: self._open_recent_path(p))

    def _open_recent_path(self, path: str):

        vault = FileVault(path)
        if vault.exists:
            self.vault_path_var.set(path)
            self._try_open(vault)
        else:
            paths = _load_recent()
            if path in paths:
                paths.remove(path)
                _save_recent(paths)
            self._update_recent_menu()
            messagebox.showwarning("提示", f"保管库路径已失效:\n{path}")

    def _manage_recent(self):

        paths = _load_recent()
        if not paths:
            messagebox.showinfo("管理最近保管库", "当前没有最近使用的保管库记录。",
                                parent=self.root)
            return

        dlg = Toplevel(self.root)
        dlg.title("管理最近保管库")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("+%d+%d" % (self.root.winfo_x() + 100, self.root.winfo_y() + 150))
        dlg.resizable(False, False)

        frame = ttk.Frame(dlg, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="最近使用的保管库路径:", font=_SF(8)).pack(
            anchor="w", pady=(0, 8))

        listbox_frame = ttk.Frame(frame)
        listbox_frame.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical")
        lb = Listbox(listbox_frame, width=70, height=10,
                             font=_SF(9), yscrollcommand=scrollbar.set)
        scrollbar.config(command=lb.yview)
        scrollbar.pack(side="right", fill="y")
        lb.pack(side="left", fill="both", expand=True)

        for p in paths:
            lb.insert("end", p)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(8, 0))

        def delete_selected():
            sel = lb.curselection()
            if not sel:
                return
            idx = sel[0]
            path = lb.get(idx)
            lb.delete(idx)
            paths2 = _load_recent()
            if path in paths2:
                paths2.remove(path)
                _save_recent(paths2)
            self._update_recent_menu()
            self.vault_combo.configure(values=_load_recent())

        def clear_all():
            if messagebox.askyesno("确认", "确定清空所有最近记录？", parent=dlg):
                _save_recent([])
                lb.delete(0, "end")
                self._update_recent_menu()
                self.vault_combo.configure(values=[])

        ttk.Button(btn_frame, text="删除选中", command=delete_selected).pack(
            side="left", padx=(0, 5))
        ttk.Button(btn_frame, text="清空全部", command=clear_all).pack(
            side="left", padx=(0, 5))
        ttk.Button(btn_frame, text="关闭", command=dlg.destroy).pack(
            side="right")

    def _on_combo_right_click(self, event):

        path = self.vault_path_var.get().strip()
        if not path:
            return
        paths = _load_recent()
        is_recent = path in paths
        self._combo_menu.entryconfig("从最近列表删除",
                                     state="normal" if is_recent else "disabled")
        self._combo_menu.post(event.x_root, event.y_root)

    def _on_combo_open(self):

        path = self.vault_path_var.get().strip()
        if path:
            vault = FileVault(path)
            if vault.exists:
                self._try_open(vault)
            else:
                messagebox.showwarning("提示", f"保管库路径无效:\n{path}")

    def _on_combo_remove(self):

        path = self.vault_path_var.get().strip()
        paths = _load_recent()
        if path in paths:
            paths.remove(path)
            _save_recent(paths)
            self._update_recent_menu()
            self.vault_combo.configure(values=paths)
            self._set_status(f"已从最近列表删除: {path}")

    def _on_combo_clear(self):

        if messagebox.askyesno("确认", "确定清空所有最近记录？", parent=self.root):
            _save_recent([])
            self._update_recent_menu()
            self.vault_combo.configure(values=[])
            self._set_status("已清空最近保管库列表")

    def _build_ui(self):
        top_frame = ttk.Frame(self.root, padding=(10, 8, 10, 5))
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text="保管库路径:", font=_SF(8)).pack(
            side="left", padx=(0, 5))

        self.vault_path_var = StringVar()

        recent_paths = _load_recent()
        self._recent_paths = recent_paths

        self.vault_combo = ttk.Combobox(
            top_frame, textvariable=self.vault_path_var,
            values=recent_paths if recent_paths else [],
            font=_SF(8), state="normal")
        self.vault_combo.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.vault_combo.bind("<<ComboboxSelected>>",
                              lambda e: self._on_recent_selected())

        self._combo_menu = tkMenu(self.root, tearoff=0)
        self._combo_menu.add_command(label="打开此保管库",
                                     command=self._on_combo_open)
        self._combo_menu.add_separator()
        self._combo_menu.add_command(label="从最近列表删除",
                                     command=self._on_combo_remove)
        self._combo_menu.add_command(label="清空最近列表",
                                     command=self._on_combo_clear)
        self.vault_combo.bind("<Button-3>", self._on_combo_right_click)

        self.browse_btn = ttk.Button(top_frame, text="浏览...", width=9,
                                     command=self._on_browse_vault)
        self.browse_btn.pack(side="left", padx=(0, 4))

        self.init_btn = ttk.Button(top_frame, text="初始化", width=7,
                                   command=self._on_init_vault)
        self.init_btn.pack(side="left", padx=(0, 4))

        self.open_btn = ttk.Button(top_frame, text="打开", width=7,
                                   command=self._on_open_vault)
        self.open_btn.pack(side="left")

        main_frame = ttk.Frame(self.root, padding=(10, 5, 10, 5))
        main_frame.pack(fill="both", expand=True)

        list_frame = ttk.LabelFrame(main_frame, text="文件列表", padding=5)
        list_frame.pack(side="left", fill="both", expand=True)

        columns = ("id", "name", "size", "added_at")
        self.tree = ttk.Treeview(list_frame, columns=columns,
                                 show="headings", selectmode="browse")
        self.tree.heading("id", text="文件 ID")
        self.tree.heading("name", text="文件名")
        self.tree.heading("size", text="大小")
        self.tree.heading("added_at", text="添加时间")
        col_scale = _DPI_SCALE
        self.tree.column("id", width=int(140 * col_scale),
                         minwidth=int(100 * col_scale))
        self.tree.column("name", width=int(180 * col_scale),
                         minwidth=int(100 * col_scale))
        self.tree.column("size", width=int(90 * col_scale),
                         minwidth=int(60 * col_scale), anchor="center")
        self.tree.column("added_at", width=int(140 * col_scale),
                         minwidth=int(100 * col_scale), anchor="center")

        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", lambda e: self._on_show_info())

        action_frame = ttk.LabelFrame(main_frame, text="快速操作", padding=10)
        action_frame.pack(side="right", fill="y", padx=(10, 0))
        action_frame.pack_propagate(False)
        action_frame.configure(width=int(200 * _DPI_SCALE))

        btn_width = 16

        self.add_btn = ttk.Button(action_frame, text="📁 添加文件", width=btn_width,
                                  command=self._on_add_file)
        self.add_btn.pack(pady=2, fill="x")

        self.move_btn = ttk.Button(action_frame, text="📦 移入文件", width=btn_width,
                                   command=self._on_move_file)
        self.move_btn.pack(pady=2, fill="x")

        self.extract_btn = ttk.Button(action_frame, text="🔓 导出文件", width=btn_width,
                                      command=self._on_extract_file)
        self.extract_btn.pack(pady=2, fill="x")

        self.del_btn = ttk.Button(action_frame, text="🗑  删除文件", width=btn_width,
                                  command=self._on_delete_file)
        self.del_btn.pack(pady=2, fill="x")

        self.info_btn = ttk.Button(action_frame, text="ℹ  查看信息", width=btn_width,
                                   command=self._on_show_info)
        self.info_btn.pack(pady=2, fill="x")

        ttk.Separator(action_frame, orient="horizontal").pack(fill="x", pady=6)

        self.passwd_btn = ttk.Button(action_frame, text="🔑 修改口令", width=btn_width,
                                     command=self._on_change_password)
        self.passwd_btn.pack(pady=2, fill="x")

        self.out_dir_var = StringVar()

        bottom_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        bottom_frame.pack(fill="x")

        self.status_var = StringVar(value="就绪 — 请新建或打开一个保管库")
        status_bar = ttk.Label(bottom_frame, textvariable=self.status_var,
                               font=_SF(8), relief="sunken",
                               anchor="w", padding=(5, 2))
        status_bar.pack(side="bottom", fill="x", pady=(3, 0))

        self.log_visible = False
        self.log_frame = ttk.Frame(bottom_frame)

        self.log_text = scrolledtext.ScrolledText(
            self.log_frame, height=6, font=_SFC(8),
            wrap="word", state="disabled", bg="#f8f8f8")
        self.log_text.pack(fill="both", expand=True)

        self.toggle_log_btn = ttk.Button(
            bottom_frame, text="显示日志 ▼", width=10,
            command=self._toggle_log)
        self.toggle_log_btn.pack(side="left", pady=(0, 3))

    def _center_window(self):
        self.root.update_idletasks()
        w, h = 960, 640
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _log(self, msg: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _toggle_log(self):
        self.log_visible = not self.log_visible
        if self.log_visible:
            self.log_frame.pack(fill="x", before=self.toggle_log_btn)
            self.toggle_log_btn.configure(text="隐藏日志 ▲")
            self._view_menu.entryconfig(2, label="隐藏日志")
        else:
            self.log_frame.pack_forget()
            self.toggle_log_btn.configure(text="显示日志 ▼")
            self._view_menu.entryconfig(2, label="显示日志")

    def _show_about(self):

        about_text = (
            "保密文件库 v1.0\n\n"
            "基于国密算法 (SM3/SM4) 的加密文件管理工具\n\n"
            "算法实现:\n"
            "  • SM3 密码杂凑 (GM/T 0004-2012)\n"
            "  • SM4 分组密码 (GM/T 0002-2012)\n"
            "  • PBKDF2-SM3 密钥派生\n\n"
            "密钥策略:\n"
            "  • 用户口令 → 主密钥 (PBKDF2-SM3)\n"
            "  • 每文件独立 SM4 密钥\n"
            "  • 密钥表加密存储"
        )
        messagebox.showinfo("关于", about_text, parent=self.root)

    def _show_help(self):

        help_text = (
            "📖 快速入门\n\n"
            "1. 初始化保管库\n"
            "   点击「初始化」→ 设置口令 → 创建保管库\n\n"
            "2. 加密文件\n"
            "   选中文件 → 点击「添加文件」(保留原件)\n"
            "   或点击「移入文件」(加密后删除原件)\n\n"
            "3. 解密文件\n"
            "   在文件列表中选中文件 → 点击「导出文件」\n"
            "   → 选择导出目录 → 解密还原\n\n"
            "4. 管理\n"
            "   • 双击文件查看详细信息\n"
            "   • 右键或选中后点击操作按钮\n"
            "   • 定期修改口令提升安全性\n\n"
            "💡 快捷键\n"
            "   Ctrl+N 新建库  Ctrl+O 打开库\n"
            "   Ctrl+A 添加    Ctrl+E 导出\n"
            "   Ctrl+I 信息    Ctrl+P 修口令\n"
            "   F5 刷新列表    Del 删除文件"
        )
        messagebox.showinfo("使用说明", help_text, parent=self.root)

    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self._log(msg)
        self.root.update_idletasks()

    def _update_ui_state(self):

        opened = self._vault is not None and self._vault.exists
        state = "normal" if opened else "disabled"
        for btn in [self.add_btn, self.move_btn, self.extract_btn,
                    self.del_btn, self.info_btn, self.passwd_btn]:
            btn.configure(state=state)

    def _get_vault_path(self) -> Optional[str]:
        path = self.vault_path_var.get().strip()
        if not path:
            messagebox.showwarning("提示", "请先输入保管库路径")
            return None
        return path

    def _on_recent_selected(self):

        path = self.vault_path_var.get().strip()
        if path:
            vault = FileVault(path)
            if vault.exists:
                self._try_open(vault)
            else:
                paths = _load_recent()
                if path in paths:
                    paths.remove(path)
                    _save_recent(paths)
                    self.vault_combo.configure(values=paths)
                messagebox.showwarning("提示", f"保管库路径已失效:\n{path}")

    def _on_browse_vault(self):
        path = filedialog.askdirectory(title="选择保管库目录")
        if path:
            self.vault_path_var.set(path)
            vault = FileVault(path)
            if vault.exists:
                self._try_open(vault)

    def _on_init_vault(self):
        path = self._get_vault_path()
        if not path:
            return
        vault = FileVault(path)
        if vault.exists:
            if not messagebox.askyesno("确认", f"保管库已存在:\n{path}\n\n确定要覆盖吗？"):
                return

        try:
            dlg = PasswordDialog(self.root, title="设置保管库口令", confirm=True)
            if dlg.result is None:
                return
            password = dlg.result

            vault2 = vault
            pw2 = password

            def task():
                vault2.init(pw2, force=True)
                return vault2

            def callback(v):
                self._vault = v
                self._password = pw2
                self._update_ui_state()
                self._on_refresh()
                _add_recent(path)
                self.vault_combo.configure(values=_load_recent())
                self._update_recent_menu()
                self._set_status(f"✓ 保管库已创建: {path}")

            self._run_bg("初始化保管库...", task, callback=callback)

        except Exception as e:
            messagebox.showerror("错误", str(e))
            self._log(f"[错误] {e}")

    def _on_open_vault(self):
        path = filedialog.askdirectory(title="选择要打开的保管库目录",
                                       parent=self.root)
        if not path:
            return
        self.vault_path_var.set(path)
        vault = FileVault(path)
        if not vault.exists:
            messagebox.showwarning("提示", f"该目录不是有效的保管库:\n{path}")
            return
        self._try_open(vault)

    def _try_open(self, vault: FileVault):

        try:
            dlg = PasswordDialog(self.root, title="打开保管库", confirm=False)
            if dlg.result is None:
                return
            password = dlg.result

            vault.list_files(password)
            self._vault = vault
            self._password = password
            self._update_ui_state()
            self._on_refresh()
            _add_recent(str(vault.path))
            self.vault_combo.configure(values=_load_recent())
            self._update_recent_menu()
            self._set_status(f"✓ 已打开保管库: {vault.path}")
            self.vault_path_var.set(str(vault.path))

        except AuthenticationError:
            messagebox.showerror("错误", "口令错误！")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def _on_add_file(self):
        self._add_or_move(delete_source=False)

    def _on_move_file(self):
        self._add_or_move(delete_source=True)

    def _add_or_move(self, delete_source: bool):
        if not self._check_vault_open():
            return
        files = filedialog.askopenfilenames(title="选择要加密的文件",
                                            parent=self.root)
        if not files:
            return
        label = "移入" if delete_source else "添加"
        password = self._password
        vault = self._vault

        def task():
            results = []
            for fp in files:
                try:
                    fid = vault.add_file(password, fp, delete_source)
                    results.append((Path(fp).name, fid, "✓"))
                except Exception as e:
                    results.append((Path(fp).name, "", f"✗ {e}"))
            return results

        def callback(results):
            ok = sum(1 for _, _, s in results if s == "✓")
            fail = len(results) - ok
            for name, fid, status in results:
                self._log(f"  [{status}] {name}" + (f"  ID: {fid}" if fid else ""))
            self._on_refresh()
            msg = f"✓ {label}完成: {ok} 个成功"
            if fail:
                msg += f", {fail} 个失败"
            self._set_status(msg)

        self._run_bg(f"正在{label}文件...", task, callback=callback)

    def _on_extract_file(self):
        if not self._check_vault_open():
            return
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先在文件列表中选择要导出的文件")
            return
        item = self.tree.item(selection[0])
        file_id = item["values"][0]
        file_name = item["values"][1]

        initial_dir = self.out_dir_var.get().strip() or None
        if initial_dir and not os.path.isdir(initial_dir):
            initial_dir = None
        out_dir = filedialog.askdirectory(
            title=f"选择导出目录 — {file_name}",
            initialdir=initial_dir,
            parent=self.root)
        if not out_dir:
            return
        self.out_dir_var.set(out_dir)

        vault = self._vault
        password = self._password

        def task():
            return vault.extract_file(password, file_id, output_dir=out_dir)

        def callback(result):
            self._set_status(f"✓ 文件已导出: {result}")

        self._run_bg("正在导出文件...", task, callback=callback)

    def _on_delete_file(self):
        if not self._check_vault_open():
            return
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先在文件列表中选择要删除的文件")
            return
        item = self.tree.item(selection[0])
        file_id = item["values"][0]
        name = item["values"][1]

        if not messagebox.askyesno("确认删除",
                                   f"确定从保管库中删除文件?\n{name} ({file_id})"):
            return

        vault = self._vault
        password = self._password

        def task():
            vault.delete_file(password, file_id)
            return name

        def callback(name):
            self._on_refresh()
            self._set_status(f"✓ 已删除: {name}")

        self._run_bg("正在删除...", task, callback=callback)

    def _on_show_info(self):
        if not self._check_vault_open():
            return
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("提示", "请先在文件列表中选择文件")
            return
        item = self.tree.item(selection[0])
        file_id = item["values"][0]

        vault = self._vault
        password = self._password

        def task():
            return vault.file_info(password, file_id)

        def callback(info):
            FileInfoDialog(self.root, info)

        self._run_bg("获取文件信息...", task, callback=callback)

    def _on_change_password(self):
        if not self._check_vault_open():
            return
        try:
            dlg = PasswordDialog(self.root, title="修改保管库口令",
                                 old_pw=True, confirm=False)
            if dlg.result is None:
                return
            old_pw = dlg.result

            dlg2 = PasswordDialog(self.root, title="设置新口令", confirm=True)
            if dlg2.result is None:
                return
            new_pw = dlg2.result

            vault = self._vault
            def task():
                vault.change_password(old_pw, new_pw)
                return new_pw

            def callback(new_pw):
                self._password = new_pw
                self._set_status("✓ 口令已修改")

            self._run_bg("修改口令...", task, callback=callback)

        except AuthenticationError:
            messagebox.showerror("错误", "当前口令错误！")

    def _on_refresh(self):
        if not self._check_vault_open():
            return
        vault = self._vault
        password = self._password

        def task():
            return vault.list_files(password)

        def callback(files):
            for item in self.tree.get_children():
                self.tree.delete(item)
            for f in files:
                self.tree.insert("", "end", values=(
                    f["id"],
                    f["name"],
                    _fmt_size(f["size"]),
                    f.get("added_at", ""),
                ))
            if not files:
                self._set_status("保管库为空 — 点击「添加文件」开始加密")
            else:
                self._set_status(f"共 {len(files)} 个文件")

        self._run_bg("刷新列表...", task, callback=callback)

    def _check_vault_open(self) -> bool:
        if self._vault is None or not self._vault.exists:
            messagebox.showwarning("提示", "请先打开一个保管库")
            return False
        return True

    def _run_bg(self, status_msg: str, task, callback=None):

        def wrapper():
            try:
                result = task()
                self.root.after(0, lambda: self._on_bg_done(
                    result, callback, None))
            except Exception as e:
                self.root.after(0, lambda e=e: self._on_bg_done(
                    None, callback, e))

        self._set_status(status_msg + "...")
        threading.Thread(target=wrapper, daemon=True).start()

    def _on_bg_done(self, result, callback, error):
        if error:
            msg = str(error)
            self._set_status(f"✗ {msg}")
            messagebox.showerror("错误", msg)
        else:
            if callback:
                callback(result)

    def run(self):
        self.root.mainloop()

def _fmt_size(n: int) -> str:
    if n <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    if i == 0:
        return f"{int(f)} B"
    return f"{f:.1f} {units[i]}"

def main():
    app = FileVaultGUI()
    app.run()

if __name__ == "__main__":
    main()

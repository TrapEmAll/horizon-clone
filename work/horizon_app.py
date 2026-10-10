"""Small dependency-free desktop front end for the clean-room parser."""

from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .horizon_clone import extract_stfs, inspect, parse_xdbf, read_stfs_entry


class HorizonApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Horizon-compatible Xbox 360 Profile Editor")
        self.geometry("1000x650")
        self.minsize(760, 460)
        self._data: bytes | None = None
        self._report = None
        self._entries = {}
        self._build_ui()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Open container", command=self.open_container).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Extract selected", command=self.extract_selected).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export report", command=self.export_report).pack(side=tk.LEFT, padx=(8, 0))
        self.status = ttk.Label(toolbar, text="Open an Xbox 360 CON/LIVE/PIRS container")
        self.status.pack(side=tk.RIGHT)

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        left = ttk.Frame(panes, padding=4)
        right = ttk.Frame(panes, padding=8)
        panes.add(left, weight=1)
        panes.add(right, weight=2)

        self.tree = ttk.Treeview(left, columns=("size", "kind"), show="tree headings")
        self.tree.heading("#0", text="Entry")
        self.tree.heading("size", text="Size")
        self.tree.heading("kind", text="Kind")
        self.tree.column("#0", width=230)
        self.tree.column("size", width=90, anchor=tk.E)
        self.tree.column("kind", width=75)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        scroll.pack(fill=tk.Y, side=tk.RIGHT)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected)

        self.details = tk.Text(right, wrap=tk.WORD, state=tk.DISABLED)
        self.details.pack(fill=tk.BOTH, expand=True)

    def _set_details(self, value: object) -> None:
        self.details.configure(state=tk.NORMAL)
        self.details.delete("1.0", tk.END)
        if isinstance(value, str):
            self.details.insert(tk.END, value)
        else:
            self.details.insert(tk.END, json.dumps(value, indent=2, ensure_ascii=False, default=str))
        self.details.configure(state=tk.DISABLED)

    def open_container(self) -> None:
        filename = filedialog.askopenfilename(title="Open Xbox 360 container")
        if not filename:
            return
        try:
            path = Path(filename)
            self._data = path.read_bytes()
            self._report = inspect(path)
            self.tree.delete(*self.tree.get_children())
            self._entries.clear()
            for entry in self._report.entries:
                item = self.tree.insert("", tk.END, text=entry.path, values=(entry.size, "DIR" if entry.is_directory else "FILE"))
                self._entries[item] = entry
            self.status.configure(text=f"{self._report.package_kind}: {len(self._report.entries)} entries")
            self._set_details({"header": self._report.stfs_header, "sha256": self._report.sha256})
        except (OSError, ValueError) as exc:
            messagebox.showerror("Open failed", str(exc))

    def show_selected(self, _event=None) -> None:
        if not self._data or not self._report:
            return
        selected = self.tree.selection()
        if not selected:
            return
        entry = self._entries[selected[0]]
        try:
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            if payload[:4] == b"XDBF":
                self._set_details({"entry": entry.path, "xdbf_entries": parse_xdbf(payload)})
            else:
                self._set_details({"entry": entry.path, "size": len(payload), "sha256": __import__("hashlib").sha256(payload).hexdigest()})
        except (OSError, ValueError, IsADirectoryError) as exc:
            self._set_details(f"Unable to read {entry.path}: {exc}")

    def extract_selected(self) -> None:
        if not self._data or not self._report:
            messagebox.showinfo("Extract", "Open a container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Extract", "Select a file first.")
            return
        entry = self._entries[selected[0]]
        target = filedialog.askdirectory(title="Extract selected file")
        if not target:
            return
        try:
            extract_stfs(self._data, Path(target), selected_path=entry.path)
            self.status.configure(text=f"Extracted {entry.path}")
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Extract failed", str(exc))

    def export_report(self) -> None:
        if not self._report:
            messagebox.showinfo("Report", "Open a container first.")
            return
        target = filedialog.asksaveasfilename(defaultextension=".json", filetypes=(("JSON", "*.json"),))
        if not target:
            return
        Path(target).write_text(json.dumps(self._report, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def main() -> int:
    HorizonApp().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


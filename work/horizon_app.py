"""Small dependency-free desktop front end for the clean-room parser."""

from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .horizon_clone import (
    extract_stfs,
    inspect,
    mutate_stfs_entry_same_size,
    mutate_stfs_metadata,
    mutate_xdbf_achievement,
    parse_xdbf,
    read_stfs_entry,
    repack_stfs_entries,
    verify_stfs_hashes,
)


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
        ttk.Button(toolbar, text="Verify hashes", command=self.verify_container).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Replace selected", command=self.replace_selected).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Repack selected", command=self.repack_selected).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Add file", command=self.add_file).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit metadata", command=self.edit_metadata).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit achievement", command=self.edit_selected_achievement).pack(side=tk.LEFT, padx=(8, 0))
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

    def verify_container(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Verify", "Open a readable STFS container first.")
            return
        try:
            result = verify_stfs_hashes(self._data, header=self._report.stfs_header)
            self._set_details(result)
            self.status.configure(text=f"Verified {result['checked_blocks']} blocks")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Verify failed", str(exc))

    def replace_selected(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Replace", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Replace", "Select a file first.")
            return
        entry = self._entries[selected[0]]
        if entry.is_directory:
            messagebox.showinfo("Replace", "Directories cannot be replaced.")
            return
        replacement_path = filedialog.askopenfilename(title="Choose same-size replacement bytes")
        if not replacement_path:
            return
        target = filedialog.asksaveasfilename(
            title="Save mutated container",
            defaultextension=".con",
            filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
        )
        if not target:
            return
        try:
            replacement = Path(replacement_path).read_bytes()
            mutated = mutate_stfs_entry_same_size(
                self._data, entry, replacement, self._report.stfs_header
            )
            Path(target).write_bytes(mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned mutation: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "signature_checked": False})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Replace failed", str(exc))

    def repack_selected(self) -> None:
        """Replace a file with a different size within existing STFS capacity."""
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Repack", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Repack", "Select a file first.")
            return
        entry = self._entries[selected[0]]
        if entry.is_directory:
            messagebox.showinfo("Repack", "Directories cannot be repacked.")
            return
        replacement_path = filedialog.askopenfilename(title="Choose replacement bytes")
        if not replacement_path:
            return
        target = filedialog.asksaveasfilename(
            title="Save repacked container",
            defaultextension=".con",
            filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
        )
        if not target:
            return
        try:
            replacement = Path(replacement_path).read_bytes()
            mutated = repack_stfs_entries(
                self._data, {entry.path: replacement}, self._report.stfs_header
            )
            Path(target).write_bytes(mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned repack: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "signature_checked": False})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Repack failed", str(exc))

    def add_file(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Add file", "Open a readable STFS container first.")
            return
        source = filedialog.askopenfilename(title="Choose file to add")
        if not source:
            return
        package_path = simpledialog.askstring(
            "Package path",
            "New package path (for example sidecar.bin or cache/sidecar.bin):",
            parent=self,
        )
        if not package_path:
            return
        target = filedialog.asksaveasfilename(
            title="Save container with added file",
            defaultextension=".con",
            filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
        )
        if not target:
            return
        try:
            mutated = repack_stfs_entries(
                self._data,
                {},
                self._report.stfs_header,
                additions={package_path: Path(source).read_bytes()},
            )
            Path(target).write_bytes(mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.tree.delete(*self.tree.get_children())
            self._entries.clear()
            for entry in self._report.entries:
                item = self.tree.insert("", tk.END, text=entry.path, values=(entry.size, "DIR" if entry.is_directory else "FILE"))
                self._entries[item] = entry
            self.status.configure(text=f"Wrote unsigned file addition: {package_path}")
            self._set_details({"path": target, "entry": package_path, "signature_checked": False})
        except (OSError, ValueError, FileNotFoundError) as exc:
            messagebox.showerror("Add file failed", str(exc))

    def edit_metadata(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Metadata", "Open a readable STFS container first.")
            return
        header = self._report.stfs_header
        display_name = simpledialog.askstring(
            "Display name", "New display name:", initialvalue=header.display_name, parent=self
        )
        if display_name is None:
            return
        title_id_text = simpledialog.askstring(
            "Title ID", "Title ID (hex, blank to keep current):", parent=self
        )
        if title_id_text is None:
            return
        try:
            title_id = header.title_id if not title_id_text.strip() else int(title_id_text, 16)
            mutated = mutate_stfs_metadata(
                self._data, display_name=display_name, title_id=title_id, header=header
            )
            target = filedialog.asksaveasfilename(
                title="Save metadata edit",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            Path(target).write_bytes(mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text="Wrote unsigned metadata edit")
            self._set_details({"path": target, "display_name": display_name, "title_id": title_id, "signature_checked": False})
        except (OSError, ValueError) as exc:
            messagebox.showerror("Metadata edit failed", str(exc))

    def edit_selected_achievement(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Achievement", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Achievement", "Select a GPD/XDBF file first.")
            return
        entry = self._entries[selected[0]]
        if entry.is_directory:
            messagebox.showinfo("Achievement", "Directories cannot be edited.")
            return
        try:
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            entries = parse_xdbf(payload)
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Achievement", f"Selected entry is not a readable XDBF file: {exc}")
            return
        achievement_entries = [item for item in entries if item.achievement is not None]
        if not achievement_entries:
            messagebox.showinfo("Achievement", "The selected XDBF has no observed achievement entries.")
            return
        index_text = simpledialog.askstring(
            "Achievement index",
            "XDBF entry index (" + ", ".join(str(item.index) for item in achievement_entries) + "):",
            parent=self,
        )
        if index_text is None:
            return
        try:
            index = int(index_text, 0)
            selected_entry = next(item for item in achievement_entries if item.index == index)
            current = selected_entry.achievement or {}
            score_text = simpledialog.askstring(
                "Gamerscore", "Gamerscore (blank to keep current):", initialvalue=str(current.get("gamerscore", "")), parent=self
            )
            if score_text is None:
                return
            flags_text = simpledialog.askstring(
                "Flags", "Flags (hex, blank to keep current):", initialvalue=hex(current.get("flags", 0)), parent=self
            )
            if flags_text is None:
                return
            name = simpledialog.askstring(
                "Achievement name", "Name (blank to keep current):", initialvalue=str(current.get("name", "")), parent=self
            )
            if name is None:
                return
            edited = mutate_xdbf_achievement(
                payload,
                index,
                gamerscore=None if not score_text.strip() else int(score_text, 0),
                flags=None if not flags_text.strip() else int(flags_text, 0),
                name=name,
            )
            mutated = mutate_stfs_entry_same_size(
                self._data, entry, edited, self._report.stfs_header
            )
            target = filedialog.asksaveasfilename(
                title="Save achievement edit",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            Path(target).write_bytes(mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned achievement edit: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "xdbf_index": index, "signature_checked": False})
        except (OSError, ValueError, StopIteration, IsADirectoryError) as exc:
            messagebox.showerror("Achievement edit failed", str(exc))

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


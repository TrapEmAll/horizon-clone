"""Small dependency-free desktop front end for the clean-room parser."""

from __future__ import annotations

import json
import tkinter as tk
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .horizon_clone import (
    add_stfs_directory,
    extract_stfs,
    inspect,
    list_embedded_achievements,
    list_embedded_xdbf,
    summarize_embedded_xdbf,
    summarize_profile_achievements,
    xdbf_payload_surface,
    mutate_stfs_entry_same_size,
    mutate_stfs_metadata,
    mutate_stfs_thumbnails,
    mutate_xdbf_achievement,
    mutate_xdbf_text,
    move_stfs_entry,
    rename_stfs_entry,
    parse_xdbf,
    parse_stfs_thumbnails,
    read_stfs_entry,
    repack_xdbf_entries,
    repack_stfs_entries,
    verify_stfs_hashes,
    editor_edit_values,
    editor_inspect_report,
    extract_managed_resource_payloads,
    anti_analysis_report,
    sign_detached_bytes,
)
from .editor_inventory import catalog_report
from .editors import AccountEditor, EditorContext


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write an artifact through a same-directory replacement."""

    temporary = path.with_name(path.name + ".horizon-tmp")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_text(path: Path, text: str) -> None:
    """Atomically write a UTF-8 text export."""

    _atomic_write_bytes(path, text.encode("utf-8"))


class HorizonApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Horizon-compatible Xbox 360 Profile Editor")
        self.geometry("1000x650")
        self.minsize(760, 460)
        self._data: bytes | None = None
        self._report = None
        self._entries = {}
        self._standalone_xdbf = False
        self._account_editor = AccountEditor()
        self._build_ui()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(fill=tk.X)
        ttk.Button(toolbar, text="Open container", command=self.open_container).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Extract selected", command=self.extract_selected).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Verify hashes", command=self.verify_container).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Security info", command=self.show_security).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Anti-analysis evidence", command=self.show_anti_analysis).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Sign loaded bytes", command=self.sign_loaded_bytes).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Replace selected", command=self.replace_selected).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Repack selected", command=self.repack_selected).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Add file", command=self.add_file).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Add directory", command=self.add_directory).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Remove entry", command=self.remove_file).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Rename file", command=self.rename_file).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Move entry", command=self.move_entry).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit metadata", command=self.edit_metadata).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit thumbnails", command=self.edit_thumbnails).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export thumbnails", command=self.export_thumbnails).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export achievements", command=self.export_achievements).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export profile summary", command=self.export_profile_summary).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export title catalog", command=self.export_title_catalog).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Extract managed resources", command=self.extract_managed_resources).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export XDBF inventory", command=self.export_xdbf_inventory).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export XDBF surface", command=self.export_xdbf_surface).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export GPD summary", command=self.export_gpd_summary).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit achievement", command=self.edit_selected_achievement).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Add XDBF entry", command=self.add_xdbf_entry).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Replace XDBF entry", command=self.replace_xdbf_entry).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit XDBF text", command=self.edit_xdbf_text).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Remove XDBF entry", command=self.remove_xdbf_entry).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Export report", command=self.export_report).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Open editor artifact", command=self.open_editor_artifact).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(toolbar, text="Edit editor artifact", command=self.edit_editor_artifact).pack(side=tk.LEFT, padx=(8, 0))
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

    def _load_standalone_xdbf(self, path: Path, data: bytes) -> None:
        self._data = data
        self._report = inspect(path)
        self._standalone_xdbf = True
        self.tree.delete(*self.tree.get_children())
        self._entries.clear()
        xdbf_entries = parse_xdbf(data)
        for entry in xdbf_entries:
            label = entry.text or (entry.achievement or {}).get("name") or ""
            item = self.tree.insert("", tk.END, text=f"XDBF[{entry.index}] {label}", values=(entry.length, "XDBF"))
            self._entries[item] = entry
        self.status.configure(text=f"Standalone XDBF: {len(xdbf_entries)} entries")
        self._set_details({"path": str(path), "xdbf_entries": xdbf_entries})

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
            self._standalone_xdbf = self._data[:4] == b"XDBF"
            if self._standalone_xdbf:
                self._load_standalone_xdbf(path, self._data)
                return
            for entry in self._report.entries:
                item = self.tree.insert("", tk.END, text=entry.path, values=(entry.size, "DIR" if entry.is_directory else "FILE"))
                self._entries[item] = entry
            self.status.configure(text=f"{self._report.package_kind}: {len(self._report.entries)} entries")
            self._set_details({"header": self._report.stfs_header, "sha256": self._report.sha256})
        except (OSError, ValueError) as exc:
            messagebox.showerror("Open failed", str(exc))

    def open_editor_artifact(self) -> None:
        """Inspect an explicit registry-supported metadata/evidence artifact."""

        filename = filedialog.askopenfilename(
            title="Open editor artifact",
            filetypes=(("JSON artifacts", "*.json"), ("All files", "*.*")),
        )
        if not filename:
            return
        try:
            path = Path(filename)
            result = editor_inspect_report(path)
            self._data = None
            self._report = None
            self._entries.clear()
            self.tree.delete(*self.tree.get_children())
            self.status.configure(text=f"Editor: {result['editor']}")
            self._set_details(result)
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Editor artifact failed", str(exc))

    def edit_editor_artifact(self) -> None:
        """Apply explicit editor values and require a separate output path."""

        filename = filedialog.askopenfilename(
            title="Open editor artifact to edit",
            filetypes=(("JSON artifacts", "*.json"), ("All files", "*.*")),
        )
        if not filename:
            return
        values_filename = filedialog.askopenfilename(
            title="Choose editor values JSON",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if not values_filename:
            return
        target = filedialog.asksaveasfilename(
            title="Save edited editor artifact",
            defaultextension=".json",
            filetypes=(("JSON artifacts", "*.json"), ("All files", "*.*")),
        )
        if not target:
            return
        if Path(target).resolve() == Path(filename).resolve():
            messagebox.showerror("Editor edit failed", "The output path must differ from the input artifact.")
            return
        try:
            editor_name, edited = editor_edit_values(Path(filename), Path(values_filename))
            _atomic_write_bytes(Path(target), edited)
            self.status.configure(text=f"Wrote {editor_name}")
            self._set_details({"editor": editor_name, "input": filename, "output": target, "bytes": len(edited)})
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Editor edit failed", str(exc))

    def sign_loaded_bytes(self) -> None:
        """Create a detached development signature for the loaded bytes."""

        if self._data is None:
            messagebox.showinfo("Detached signing", "Open an artifact first.")
            return
        label = simpledialog.askstring("Signature label", "Caller-defined development region label:", parent=self)
        if not label:
            return
        key = filedialog.askopenfilename(
            title="Choose development private-key JSON",
            filetypes=(("Private-key JSON", "*.json"), ("All files", "*.*")),
        )
        if not key:
            return
        target = filedialog.asksaveasfilename(
            title="Save detached signature",
            defaultextension=".sig",
            filetypes=(("Signature", "*.sig"), ("All files", "*.*")),
        )
        if not target:
            return
        try:
            result = sign_detached_bytes(self._data, Path(target), label, Path(key))
            self.status.configure(text="Wrote detached development signature")
            self._set_details(result)
        except (OSError, TypeError, ValueError) as exc:
            messagebox.showerror("Detached signing failed", str(exc))

    def show_anti_analysis(self) -> None:
        """Display retained REA anti-analysis observations without execution."""

        bundle = filedialog.askopenfilename(
            title="Choose REA evidence bundle",
            filetypes=(("JSON evidence", "*.json"), ("All files", "*.*")),
        )
        if not bundle:
            return
        try:
            report = anti_analysis_report(Path(bundle))
            self.status.configure(text="Displayed anti-analysis evidence")
            self._set_details(report)
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Anti-analysis report failed", str(exc))

    def show_selected(self, _event=None) -> None:
        if not self._data or not self._report:
            return
        selected = self.tree.selection()
        if not selected:
            return
        entry = self._entries[selected[0]]
        if self._standalone_xdbf:
            self._set_details({"xdbf_entry": entry})
            return
        try:
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            if self._account_editor.can_edit(EditorContext(filename=entry.path), payload):
                self._set_details({"entry": entry.path, "account": self._account_editor.inspect(EditorContext(filename=entry.path), payload)})
            elif payload[:4] == b"XDBF":
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

    def show_security(self) -> None:
        if not self._report or not self._report.stfs_security:
            messagebox.showinfo("Security", "Open a readable STFS container first.")
            return
        self._set_details({
            "security": self._report.stfs_security,
            "signature_validity_checked": False,
        })
        self.status.configure(text="Displayed public security metadata; signature validity not checked")

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
            _atomic_write_bytes(Path(target), mutated)
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
            _atomic_write_bytes(Path(target), mutated)
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
            _atomic_write_bytes(Path(target), mutated)
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

    def remove_file(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header or self._standalone_xdbf:
            messagebox.showinfo("Remove entry", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Remove entry", "Select an entry first.")
            return
        entry = self._entries[selected[0]]
        if not messagebox.askyesno("Remove entry", f"Remove {entry.path}?", parent=self):
            return
        try:
            mutated = repack_stfs_entries(self._data, {}, remove=(entry.path,), header=self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Save container without file",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.tree.delete(*self.tree.get_children())
            self._entries.clear()
            for item in self._report.entries:
                tree_item = self.tree.insert("", tk.END, text=item.path, values=(item.size, "DIR" if item.is_directory else "FILE"))
                self._entries[tree_item] = item
            self.status.configure(text=f"Wrote unsigned entry removal: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "signature_checked": False})
        except (OSError, ValueError, FileNotFoundError, IsADirectoryError) as exc:
            messagebox.showerror("Remove entry failed", str(exc))

    def add_directory(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header or self._standalone_xdbf:
            messagebox.showinfo("Add directory", "Open a readable STFS container first.")
            return
        directory_path = simpledialog.askstring("Add directory", "Directory path:", parent=self)
        if not directory_path:
            return
        try:
            mutated = add_stfs_directory(self._data, directory_path, self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Save container with directory",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.tree.delete(*self.tree.get_children())
            self._entries.clear()
            for item in self._report.entries:
                tree_item = self.tree.insert("", tk.END, text=item.path, values=(item.size, "DIR" if item.is_directory else "FILE"))
                self._entries[tree_item] = item
            self.status.configure(text=f"Wrote unsigned directory addition: {directory_path}")
            self._set_details({"path": target, "directory": directory_path, "signature_checked": False})
        except (OSError, ValueError, FileNotFoundError) as exc:
            messagebox.showerror("Add directory failed", str(exc))

    def rename_file(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header or self._standalone_xdbf:
            messagebox.showinfo("Rename file", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Rename file", "Select a file first.")
            return
        entry = self._entries[selected[0]]
        new_name = simpledialog.askstring("Rename file", "New ASCII basename:", initialvalue=entry.name, parent=self)
        if new_name is None:
            return
        try:
            mutated = rename_stfs_entry(self._data, entry.path, new_name, self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Save renamed container",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.tree.delete(*self.tree.get_children())
            self._entries.clear()
            for item in self._report.entries:
                tree_item = self.tree.insert("", tk.END, text=item.path, values=(item.size, "DIR" if item.is_directory else "FILE"))
                self._entries[tree_item] = item
            self.status.configure(text=f"Wrote unsigned file rename: {entry.path} -> {new_name}")
            self._set_details({"path": target, "entry": entry.path, "new_name": new_name, "signature_checked": False})
        except (OSError, ValueError, FileNotFoundError, IsADirectoryError) as exc:
            messagebox.showerror("Rename file failed", str(exc))

    def move_entry(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header or self._standalone_xdbf:
            messagebox.showinfo("Move entry", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Move entry", "Select an entry first.")
            return
        entry = self._entries[selected[0]]
        destination = simpledialog.askstring("Move entry", "Destination directory path:", parent=self)
        if not destination:
            return
        new_name = simpledialog.askstring("Move entry", "New ASCII basename (blank keeps current name):", initialvalue=entry.name, parent=self)
        if new_name is None:
            return
        try:
            mutated = move_stfs_entry(self._data, entry.path, destination, new_name or None, self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Save moved container",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.tree.delete(*self.tree.get_children())
            self._entries.clear()
            for item in self._report.entries:
                tree_item = self.tree.insert("", tk.END, text=item.path, values=(item.size, "DIR" if item.is_directory else "FILE"))
                self._entries[tree_item] = item
            final_name = new_name or entry.name
            self.status.configure(text=f"Wrote unsigned entry move: {entry.path} -> {destination}/{final_name}")
            self._set_details({"path": target, "entry": entry.path, "destination": destination, "new_name": final_name, "signature_checked": False})
        except (OSError, ValueError, FileNotFoundError, IsADirectoryError) as exc:
            messagebox.showerror("Move entry failed", str(exc))

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
            "Title ID", "Title ID (hex, blank to keep current):", initialvalue=f"0x{header.title_id:08X}", parent=self
        )
        if title_id_text is None:
            return
        content_type_text = simpledialog.askstring(
            "Content type",
            "Content type (hex, blank to keep current):",
            initialvalue=f"0x{header.content_type:08X}",
            parent=self,
        )
        if content_type_text is None:
            return
        description = simpledialog.askstring(
            "Description", "Display description:", initialvalue=header.display_description, parent=self
        )
        if description is None:
            return
        publisher = simpledialog.askstring(
            "Publisher", "Publisher name:", initialvalue=header.publisher_name, parent=self
        )
        if publisher is None:
            return
        title_name = simpledialog.askstring(
            "Title name", "Title name:", initialvalue=header.title_name, parent=self
        )
        if title_name is None:
            return
        transfer_flags_text = simpledialog.askstring(
            "Transfer flags",
            "Transfer flags (hex, blank to keep current):",
            initialvalue=f"0x{header.transfer_flags:02X}",
            parent=self,
        )
        if transfer_flags_text is None:
            return
        try:
            title_id = header.title_id if not title_id_text.strip() else int(title_id_text, 16)
            content_type = header.content_type if not content_type_text.strip() else int(content_type_text, 16)
            transfer_flags = header.transfer_flags if not transfer_flags_text.strip() else int(transfer_flags_text, 16)
            mutated = mutate_stfs_metadata(
                self._data,
                display_name=display_name,
                display_description=description,
                publisher_name=publisher,
                title_name=title_name,
                transfer_flags=transfer_flags,
                title_id=title_id,
                content_type=content_type,
                header=header,
            )
            target = filedialog.asksaveasfilename(
                title="Save metadata edit",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text="Wrote unsigned metadata edit")
            self._set_details(
                {
                    "path": target,
                    "display_name": display_name,
                    "display_description": description,
                    "publisher_name": publisher,
                    "title_name": title_name,
                    "title_id": title_id,
                    "content_type": content_type,
                    "transfer_flags": transfer_flags,
                    "signature_checked": False,
                }
            )
        except (OSError, ValueError) as exc:
            messagebox.showerror("Metadata edit failed", str(exc))

    def _save_standalone_xdbf(self, data: bytes, title: str, status: str) -> bool:
        target = filedialog.asksaveasfilename(
            title=title,
            defaultextension=".gpd",
            filetypes=(("GPD/XDBF", "*.gpd *.xdbf"), ("All files", "*.*")),
        )
        if not target:
            return False
        path = Path(target)
        _atomic_write_bytes(path, data)
        self._load_standalone_xdbf(path, data)
        self.status.configure(text=status)
        return True

    def _edit_standalone_achievement(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Achievement", "Select an XDBF entry first.")
            return
        selected_entry = self._entries[selected[0]]
        current = selected_entry.achievement or {}
        if not current:
            messagebox.showinfo("Achievement", "The selected entry is not an achievement payload.")
            return
        score_text = simpledialog.askstring("Gamerscore", "Gamerscore:", initialvalue=str(current.get("gamerscore", "")), parent=self)
        flags_text = simpledialog.askstring("Flags", "Flags:", initialvalue=hex(current.get("flags", 0)), parent=self)
        name = simpledialog.askstring("Achievement name", "Name:", initialvalue=str(current.get("name", "")), parent=self)
        if score_text is None or flags_text is None or name is None:
            return
        edited = mutate_xdbf_achievement(
            self._data,
            selected_entry.index,
            gamerscore=int(score_text, 0),
            flags=int(flags_text, 0),
            name=name,
        )
        self._save_standalone_xdbf(edited, "Save standalone achievement edit", "Wrote unsigned standalone achievement edit")

    def edit_selected_achievement(self) -> None:
        if self._standalone_xdbf:
            try:
                self._edit_standalone_achievement()
            except (OSError, ValueError, StopIteration) as exc:
                messagebox.showerror("Achievement edit failed", str(exc))
            return
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
            mutated = repack_stfs_entries(
                self._data, {entry.path: edited}, self._report.stfs_header
            )
            target = filedialog.asksaveasfilename(
                title="Save achievement edit",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned achievement edit: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "xdbf_index": index, "signature_checked": False})
        except (OSError, ValueError, StopIteration, IsADirectoryError) as exc:
            messagebox.showerror("Achievement edit failed", str(exc))

    def edit_thumbnails(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Thumbnails", "Open a readable STFS container first.")
            return
        try:
            thumbnail_path = filedialog.askopenfilename(
                title="Choose thumbnail (Cancel to keep current)",
                filetypes=(("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")),
            )
            title_thumbnail_path = filedialog.askopenfilename(
                title="Choose title thumbnail (Cancel to keep current)",
                filetypes=(("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")),
            )
            if not thumbnail_path and not title_thumbnail_path:
                return
            mutated = mutate_stfs_thumbnails(
                self._data,
                thumbnail=Path(thumbnail_path).read_bytes() if thumbnail_path else None,
                title_thumbnail=Path(title_thumbnail_path).read_bytes() if title_thumbnail_path else None,
                header=self._report.stfs_header,
            )
            target = filedialog.asksaveasfilename(
                title="Save thumbnail edit",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text="Wrote unsigned thumbnail mutation")
            self._set_details({"path": target, "signature_checked": False})
        except (OSError, ValueError) as exc:
            messagebox.showerror("Thumbnail edit failed", str(exc))

    def export_thumbnails(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Thumbnails", "Open a readable STFS container first.")
            return
        try:
            thumbnails = parse_stfs_thumbnails(self._data, self._report.stfs_header)
            thumbnail_path = filedialog.asksaveasfilename(
                title="Save thumbnail payload",
                defaultextension=".bin",
                filetypes=(("Binary payload", "*.bin"), ("All files", "*.*")),
            )
            if not thumbnail_path:
                return
            title_path = filedialog.asksaveasfilename(
                title="Save title-thumbnail payload",
                defaultextension=".bin",
                filetypes=(("Binary payload", "*.bin"), ("All files", "*.*")),
            )
            if not title_path:
                return
            _atomic_write_bytes(Path(thumbnail_path), thumbnails.thumbnail)
            _atomic_write_bytes(Path(title_path), thumbnails.title_thumbnail)
            self.status.configure(text="Exported thumbnail payloads")
            self._set_details({"thumbnail": thumbnail_path, "title_thumbnail": title_path})
        except (OSError, ValueError) as exc:
            messagebox.showerror("Thumbnail export failed", str(exc))

    def export_achievements(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Achievements", "Open a readable STFS profile first.")
            return
        try:
            achievements = list(list_embedded_achievements(self._data, self._report.stfs_header))
            target = filedialog.asksaveasfilename(
                title="Export achievements",
                defaultextension=".json",
                filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_text(Path(target), json.dumps(achievements, indent=2, ensure_ascii=False) + "\n")
            self.status.configure(text=f"Exported {len(achievements)} achievements")
            self._set_details({"path": target, "achievement_count": len(achievements)})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Achievement export failed", str(exc))

    def export_profile_summary(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("Profile summary", "Open a readable STFS profile first.")
            return
        try:
            summary = summarize_profile_achievements(self._data, self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Export profile summary",
                defaultextension=".json",
                filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_text(Path(target), json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
            self.status.configure(text="Exported profile summary")
            self._set_details({"path": target, "summary": summary})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Profile summary export failed", str(exc))

    def export_title_catalog(self) -> None:
        catalog_name = simpledialog.askstring(
            "Title catalog",
            "Catalog name (shared, skyrim, gears, halo, legacy, or global):",
            parent=self,
        )
        if not catalog_name:
            return
        try:
            catalog = catalog_report(catalog_name.strip().lower())
            target = filedialog.asksaveasfilename(
                title=f"Export {catalog_name} catalog",
                defaultextension=".json",
                filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_text(Path(target), json.dumps(catalog, indent=2, ensure_ascii=False) + "\n")
            self.status.configure(text=f"Exported {catalog_name} catalog")
            self._set_details({"path": target, "catalog": catalog_name, "catalog_keys": list(catalog)})
        except (KeyError, OSError, TypeError, ValueError) as exc:
            messagebox.showerror("Catalog export failed", str(exc))

    def extract_managed_resources(self) -> None:
        """Export only REA-hash-verified managed resources from Horizon.exe."""

        executable = filedialog.askopenfilename(
            title="Choose Horizon executable",
            filetypes=(("Horizon executable", "Horizon.exe"), ("PE files", "*.exe"), ("All files", "*.*")),
        )
        if not executable:
            return
        bundle = filedialog.askopenfilename(
            title="Choose REA managed-resource bundle",
            filetypes=(("JSON evidence", "*.json"), ("All files", "*.*")),
        )
        if not bundle:
            return
        output_dir = filedialog.askdirectory(title="Choose resource output directory")
        if not output_dir:
            return
        pattern = simpledialog.askstring(
            "Resource filter",
            "Optional case-insensitive resource-name regex (leave blank for all):",
            parent=self,
        )
        try:
            report = extract_managed_resource_payloads(executable, bundle, output_dir, pattern or None)
            self.status.configure(text=f"Extracted {report['counts']['extracted']} managed resources")
            self._set_details(report)
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("Managed-resource extraction failed", str(exc))

    def export_xdbf_inventory(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("XDBF inventory", "Open a readable STFS profile first.")
            return
        inventory = []
        for entry, xdbf_entries in list_embedded_xdbf(self._data, self._report.stfs_header):
            for xdbf_entry in xdbf_entries:
                inventory.append(
                    {
                        "file": entry.path,
                        "index": xdbf_entry.index,
                        "namespace": xdbf_entry.namespace,
                        "entry_id": xdbf_entry.entry_id,
                        "offset": xdbf_entry.offset,
                        "length": xdbf_entry.length,
                        "data_offset": xdbf_entry.data_offset,
                        "text": xdbf_entry.text,
                        "achievement": xdbf_entry.achievement,
                    }
                )
        target = filedialog.asksaveasfilename(
            title="Export XDBF inventory",
            defaultextension=".json",
            filetypes=(("JSON", "*.json"), ("All files", "*.*")),
        )
        if not target:
            return
        try:
            _atomic_write_text(Path(target), json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
            self.status.configure(text=f"Exported {len(inventory)} XDBF entries")
            self._set_details({"path": target, "xdbf_entry_count": len(inventory)})
        except OSError as exc:
            messagebox.showerror("XDBF inventory export failed", str(exc))

    def export_gpd_summary(self) -> None:
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("GPD summary", "Open a readable STFS profile first.")
            return
        try:
            summary = list(summarize_embedded_xdbf(self._data, self._report.stfs_header))
            target = filedialog.asksaveasfilename(
                title="Export GPD summary",
                defaultextension=".json",
                filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_text(Path(target), json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
            self.status.configure(text=f"Exported {len(summary)} GPD summaries")
            self._set_details({"path": target, "gpd_count": len(summary)})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("GPD summary export failed", str(exc))

    def export_xdbf_surface(self) -> None:
        """Export payload digests for standalone or embedded XDBF files."""

        if not self._data or not self._report:
            messagebox.showinfo("XDBF surface", "Open an XDBF file or STFS profile first.")
            return
        try:
            surface: list[dict[str, object]] = []
            if self._standalone_xdbf:
                for item in xdbf_payload_surface(self._data):
                    surface.append({"file": str(self._report.path), **item})
            elif self._report.stfs_header:
                for entry, _ in list_embedded_xdbf(self._data, self._report.stfs_header):
                    payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
                    for item in xdbf_payload_surface(payload):
                        surface.append({"file": entry.path, **item})
            else:
                messagebox.showinfo("XDBF surface", "The selected artifact has no readable XDBF payloads.")
                return
            target = filedialog.asksaveasfilename(
                title="Export XDBF payload surface",
                defaultextension=".json",
                filetypes=(("JSON", "*.json"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_text(Path(target), json.dumps(surface, indent=2, ensure_ascii=False) + "\n")
            self.status.configure(text=f"Exported {len(surface)} XDBF payload records")
            self._set_details({"path": target, "xdbf_payload_count": len(surface)})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("XDBF surface export failed", str(exc))

    def add_xdbf_entry(self) -> None:
        if self._standalone_xdbf:
            try:
                namespace_text = simpledialog.askstring("XDBF namespace", "Namespace (integer or hex):", parent=self)
                entry_id_text = simpledialog.askstring("XDBF entry ID", "Entry ID (integer or hex):", parent=self)
                if namespace_text is None or entry_id_text is None:
                    return
                source = filedialog.askopenfilename(title="Choose XDBF payload")
                if not source:
                    return
                edited = repack_xdbf_entries(
                    self._data,
                    {},
                    additions={(int(namespace_text, 0), int(entry_id_text, 0)): Path(source).read_bytes()},
                )
                self._save_standalone_xdbf(edited, "Save standalone XDBF entry addition", "Wrote unsigned standalone XDBF entry addition")
            except (OSError, ValueError) as exc:
                messagebox.showerror("XDBF entry addition failed", str(exc))
            return
        if not self._data or not self._report or not self._report.stfs_header:
            messagebox.showinfo("XDBF entry", "Open a readable STFS container first.")
            return
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("XDBF entry", "Select a GPD/XDBF file first.")
            return
        entry = self._entries[selected[0]]
        if entry.is_directory:
            messagebox.showinfo("XDBF entry", "Directories cannot be edited.")
            return
        try:
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            parse_xdbf(payload)
            namespace_text = simpledialog.askstring("XDBF namespace", "Namespace (integer or hex):", parent=self)
            entry_id_text = simpledialog.askstring("XDBF entry ID", "Entry ID (integer or hex):", parent=self)
            if namespace_text is None or entry_id_text is None:
                return
            source = filedialog.askopenfilename(title="Choose XDBF payload")
            if not source:
                return
            edited = repack_xdbf_entries(
                payload,
                {},
                additions={(int(namespace_text, 0), int(entry_id_text, 0)): Path(source).read_bytes()},
            )
            mutated = repack_stfs_entries(self._data, {entry.path: edited}, self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Save XDBF entry addition",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned XDBF entry addition: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "signature_checked": False})
        except (OSError, ValueError, IsADirectoryError) as exc:
            messagebox.showerror("XDBF entry addition failed", str(exc))

    def replace_xdbf_entry(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("XDBF entry", "Select an XDBF entry first.")
            return
        entry = self._entries[selected[0]]
        try:
            source = filedialog.askopenfilename(title="Choose replacement XDBF payload")
            if not source:
                return
            if self._standalone_xdbf:
                edited = repack_xdbf_entries(self._data, {entry.index: Path(source).read_bytes()})
                self._save_standalone_xdbf(edited, "Save standalone XDBF replacement", "Wrote unsigned standalone XDBF replacement")
                return
            if not self._report or not self._report.stfs_header or entry.is_directory:
                messagebox.showinfo("XDBF entry", "Select a readable GPD/XDBF file first.")
                return
            index_text = simpledialog.askstring("XDBF entry index", "Entry index to replace:", parent=self)
            if index_text is None:
                return
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            edited_payload = repack_xdbf_entries(payload, {int(index_text, 0): Path(source).read_bytes()})
            mutated = repack_stfs_entries(self._data, {entry.path: edited_payload}, self._report.stfs_header)
            target = filedialog.asksaveasfilename(title="Save embedded XDBF replacement", defaultextension=".con", filetypes=(("Xbox content", "*.con"), ("All files", "*.*")))
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned embedded XDBF replacement: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "xdbf_index": int(index_text, 0), "signature_checked": False})
        except (OSError, ValueError, IndexError, StopIteration, IsADirectoryError) as exc:
            messagebox.showerror("XDBF replacement failed", str(exc))

    def edit_xdbf_text(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("XDBF text", "Select an XDBF entry first.")
            return
        entry = self._entries[selected[0]]
        try:
            if self._standalone_xdbf:
                if entry.text is None:
                    messagebox.showinfo("XDBF text", "The selected entry is not an observed namespace-5 string.")
                    return
                value = simpledialog.askstring("XDBF text", "Replacement text:", initialvalue=entry.text, parent=self)
                if value is None:
                    return
                edited = mutate_xdbf_text(self._data, entry.index, value)
                self._save_standalone_xdbf(edited, "Save standalone XDBF text edit", "Wrote unsigned standalone XDBF text edit")
                return
            if not self._report or not self._report.stfs_header or entry.is_directory:
                messagebox.showinfo("XDBF text", "Select a readable GPD/XDBF file first.")
                return
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            xdbf_entries = parse_xdbf(payload)
            text_entries = [item for item in xdbf_entries if item.text is not None]
            if not text_entries:
                messagebox.showinfo("XDBF text", "The selected file has no observed namespace-5 strings.")
                return
            index_text = simpledialog.askstring(
                "XDBF text index",
                "Entry index (" + ", ".join(str(item.index) for item in text_entries) + "):",
                parent=self,
            )
            if index_text is None:
                return
            selected_text = next(item for item in text_entries if item.index == int(index_text, 0))
            value = simpledialog.askstring("XDBF text", "Replacement text:", initialvalue=selected_text.text, parent=self)
            if value is None:
                return
            edited_payload = mutate_xdbf_text(payload, selected_text.index, value)
            mutated = repack_stfs_entries(self._data, {entry.path: edited_payload}, self._report.stfs_header)
            target = filedialog.asksaveasfilename(
                title="Save embedded XDBF text edit",
                defaultextension=".con",
                filetypes=(("Xbox content", "*.con"), ("All files", "*.*")),
            )
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned embedded XDBF text edit: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "xdbf_index": selected_text.index, "signature_checked": False})
        except (OSError, ValueError, IndexError, StopIteration) as exc:
            messagebox.showerror("XDBF text edit failed", str(exc))

    def remove_xdbf_entry(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("XDBF entry", "Select an XDBF entry first.")
            return
        entry = self._entries[selected[0]]
        if not messagebox.askyesno("Remove XDBF entry", f"Remove entry {entry.index}?", parent=self):
            return
        try:
            if self._standalone_xdbf:
                edited = repack_xdbf_entries(self._data, {}, remove=(entry.index,))
                self._save_standalone_xdbf(edited, "Save standalone XDBF removal", "Wrote unsigned standalone XDBF removal")
                return
            if not self._report or not self._report.stfs_header or entry.is_directory:
                messagebox.showinfo("XDBF entry", "Select a readable GPD/XDBF file first.")
                return
            index_text = simpledialog.askstring("XDBF entry index", "Entry index to remove:", parent=self)
            if index_text is None:
                return
            payload = read_stfs_entry(self._data, entry, self._report.stfs_header)
            edited_payload = repack_xdbf_entries(payload, {}, remove=(int(index_text, 0),))
            mutated = repack_stfs_entries(self._data, {entry.path: edited_payload}, self._report.stfs_header)
            target = filedialog.asksaveasfilename(title="Save embedded XDBF removal", defaultextension=".con", filetypes=(("Xbox content", "*.con"), ("All files", "*.*")))
            if not target:
                return
            _atomic_write_bytes(Path(target), mutated)
            self._data = mutated
            self._report = inspect(Path(target))
            self.status.configure(text=f"Wrote unsigned embedded XDBF removal: {entry.path}")
            self._set_details({"path": target, "entry": entry.path, "xdbf_index": int(index_text, 0), "signature_checked": False})
        except (OSError, ValueError, IndexError, IsADirectoryError) as exc:
            messagebox.showerror("XDBF removal failed", str(exc))

    def export_report(self) -> None:
        if not self._report:
            messagebox.showinfo("Report", "Open a container first.")
            return
        target = filedialog.asksaveasfilename(defaultextension=".json", filetypes=(("JSON", "*.json"),))
        if not target:
            return
        report = asdict(self._report)
        report["is_container"] = self._report.is_container
        _atomic_write_text(Path(target), json.dumps(report, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    HorizonApp().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


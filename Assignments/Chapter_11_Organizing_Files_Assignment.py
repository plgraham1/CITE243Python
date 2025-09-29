"""
===========================================================
Program Name: File Management Toolkit (GUI)
Author: Your Name
Date: 2025-09-29
Description:
    GUI version of the File Management Toolkit using Tkinter.
    Provides buttons and dialogs for:
    1. Selectively Copy Files
    2. Find Large Files
    3. Renumber Files
    4. Convert American to European Date Filenames

Usage:
    Run with Python 3.x:
        python3 file_tools_gui.py
===========================================================
"""

import os
import shutil
import re
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# ---------- Utility Functions ----------
def human_readable_size(size_in_bytes):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_in_bytes < 1024:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024


# ---------- Core Features ----------
def selective_copy():
    src = filedialog.askdirectory(title="Select Source Folder")
    if not src:
        return
    dest = filedialog.askdirectory(title="Select Destination Folder")
    if not dest:
        return
    ext = simple_input("Enter file extension (e.g., .jpg, .pdf):")
    if not ext:
        return

    copied = []
    for foldername, _, filenames in os.walk(src):
        for filename in filenames:
            if filename.lower().endswith(ext.lower()):
                src_path = os.path.join(foldername, filename)
                dest_path = os.path.join(dest, filename)
                if not os.path.exists(dest_path):
                    shutil.copy2(src_path, dest_path)
                    copied.append((filename, "Copied", src_path))
                else:
                    copied.append((filename, "Skipped (Exists)", src_path))

    show_results("Selective Copy Results", ["File", "Action", "Path"], copied)


def find_large_files():
    src = filedialog.askdirectory(title="Select Folder to Scan")
    if not src:
        return
    size = simple_input("Enter size threshold (default 100):", "100")
    unit = simple_input("Enter unit (KB/MB/GB, default MB):", "MB").upper()
    size = int(size)

    multiplier = {"KB": 1024, "MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}.get(unit, 1024 * 1024)
    threshold = size * multiplier

    found = []
    for foldername, _, filenames in os.walk(src):
        for filename in filenames:
            path = os.path.join(foldername, filename)
            try:
                size_bytes = os.path.getsize(path)
                if size_bytes > threshold:
                    found.append((filename, human_readable_size(size_bytes), path))
            except Exception:
                pass

    show_results("Large Files Found", ["File", "Size", "Path"], found)


def renumber_files():
    folder = filedialog.askdirectory(title="Select Folder")
    if not folder:
        return
    prefix = simple_input("Enter filename prefix (e.g., spam):")
    ext = simple_input("Enter file extension (e.g., .txt):")

    files = []
    regex = re.compile(rf"^{re.escape(prefix)}(\d+){re.escape(ext)}$")
    for f in os.listdir(folder):
        match = regex.match(f)
        if match:
            files.append((int(match.group(1)), f))

    files.sort()
    expected = 1
    results = []
    for num, fname in files:
        full_path = os.path.join(folder, fname)
        if num != expected:
            new_name = f"{prefix}{str(expected).zfill(3)}{ext}"
            os.rename(full_path, os.path.join(folder, new_name))
            results.append((fname, f"Renamed to {new_name}", full_path))
        else:
            results.append((fname, "OK", full_path))
        expected += 1

    show_results("Renumber Results", ["Original File", "Status", "Path"], results)


def convert_dates():
    src = filedialog.askdirectory(title="Select Folder to Scan")
    if not src:
        return
    date_pattern = re.compile(r"""^(.*?)
        (\d{2})-(\d{2})-(\d{4})   # MM-DD-YYYY
        (.*?)$
        """, re.VERBOSE)

    renamed = []
    for foldername, _, filenames in os.walk(src):
        for filename in filenames:
            mo = date_pattern.search(filename)
            if mo:
                before, mm, dd, yyyy, after = mo.groups()
                euro_filename = f"{before}{dd}-{mm}-{yyyy}{after}"
                src_path = os.path.join(foldername, filename)
                dest_path = os.path.join(foldername, euro_filename)
                shutil.move(src_path, dest_path)
                renamed.append((filename, euro_filename, src_path))

    show_results("Date Conversion Results", ["Original File", "New File", "Path"], renamed)


# ---------- Helper Dialogs ----------
def simple_input(prompt, default=""):
    """Prompt user for a simple string input."""
    popup = tk.Toplevel(root)
    popup.title("Input Required")

    tk.Label(popup, text=prompt).pack(pady=5)
    entry = tk.Entry(popup)
    entry.insert(0, default)
    entry.pack(pady=5)

    result = []

    def submit():
        result.append(entry.get())
        popup.destroy()

    tk.Button(popup, text="OK", command=submit).pack(pady=5)
    popup.grab_set()
    root.wait_window(popup)
    return result[0] if result else None


# ---------- Results Table with CSV Export ----------
def show_results(title, headers, rows):
    result_window = tk.Toplevel(root)
    result_window.title(title)
    result_window.geometry("700x400")

    tree = ttk.Treeview(result_window, columns=headers, show="headings")
    for h in headers:
        tree.heading(h, text=h)
        tree.column(h, width=200)
    for row in rows:
        tree.insert("", "end", values=row)

    tree.pack(fill="both", expand=True)

    def save_csv():
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save Results As"
        )
        if filepath:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            messagebox.showinfo("Export Complete", f"Results saved to:\n{filepath}")

    ttk.Button(result_window, text="Save to CSV", command=save_csv).pack(pady=10)


# ---------- Main GUI ----------
root = tk.Tk()
root.title("File Management Toolkit")
root.geometry("500x300")

frame = ttk.Frame(root, padding=20)
frame.pack(fill="both", expand=True)

ttk.Button(frame, text="Selectively Copy Files", command=selective_copy).pack(fill="x", pady=5)
ttk.Button(frame, text="Find Large Files", command=find_large_files).pack(fill="x", pady=5)
ttk.Button(frame, text="Renumber Files", command=renumber_files).pack(fill="x", pady=5)
ttk.Button(frame, text="Convert Dates (MM-DD-YYYY ? DD-MM-YYYY)", command=convert_dates).pack(fill="x", pady=5)

ttk.Button(frame, text="Exit", command=root.quit).pack(fill="x", pady=20)

root.mainloop()

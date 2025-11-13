# ============================================================
# File Tools Panel
# ============================================================

import os
import shutil
from pathlib import Path
from PySide6 import QtCore, QtWidgets
from helpers import ensure_folder


class FileToolsPanel(QtWidgets.QWidget):
    """
    Provides file management tools:
    - List files in a folder
    - Copy or move files
    - Delete selected files
    - Search by name pattern
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("File Tools")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        desc = QtWidgets.QLabel("Use these tools to manage files and folders.")
        layout.addWidget(desc)

        # --- Folder input
        folder_layout = QtWidgets.QHBoxLayout()
        self.folder_edit = QtWidgets.QLineEdit()
        self.folder_edit.setPlaceholderText("Select a folder...")
        browse_btn = QtWidgets.QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_folder)
        folder_layout.addWidget(self.folder_edit)
        folder_layout.addWidget(browse_btn)
        layout.addLayout(folder_layout)

        # --- Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        self.list_btn = QtWidgets.QPushButton("List Files")
        self.delete_btn = QtWidgets.QPushButton("Delete Selected")
        self.copy_btn = QtWidgets.QPushButton("Copy Selected")
        self.search_btn = QtWidgets.QPushButton("Search by Name")

        btn_layout.addWidget(self.list_btn)
        btn_layout.addWidget(self.copy_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addWidget(self.search_btn)
        layout.addLayout(btn_layout)

        # --- File list
        self.file_list = QtWidgets.QListWidget()
        self.file_list.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        layout.addWidget(self.file_list)

        # --- Status log
        self.log = QtWidgets.QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        # --- Connections
        self.list_btn.clicked.connect(self.list_files)
        self.copy_btn.clicked.connect(self.copy_files)
        self.delete_btn.clicked.connect(self.delete_files)
        self.search_btn.clicked.connect(self.search_files)

    # ------------------------------------------------------------
    # Folder browser
    # ------------------------------------------------------------
    def browse_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select Folder", str(Path.home())
        )
        if path:
            self.folder_edit.setText(path)

    # ------------------------------------------------------------
    # List files in folder
    # ------------------------------------------------------------
    def list_files(self):
        folder = self.folder_edit.text().strip()
        if not folder or not os.path.isdir(folder):
            self.log.append("Error: Invalid folder.")
            return
        self.file_list.clear()
        for name in os.listdir(folder):
            full_path = os.path.join(folder, name)
            if os.path.isfile(full_path):
                self.file_list.addItem(name)
        self.log.append("Files listed from: " + folder)

    # ------------------------------------------------------------
    # Copy selected files to target folder
    # ------------------------------------------------------------
    def copy_files(self):
        folder = self.folder_edit.text().strip()
        if not folder:
            self.log.append("Error: No source folder selected.")
            return
        dest = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select Destination Folder", str(Path.home())
        )
        if not dest:
            return

        for item in self.file_list.selectedItems():
            src_file = Path(folder) / item.text()
            dest_file = Path(dest) / item.text()
            try:
                shutil.copy2(src_file, dest_file)
                self.log.append("Copied: " + str(dest_file))
            except Exception as e:
                self.log.append("Error copying " + str(src_file) + ": " + str(e))

    # ------------------------------------------------------------
    # Delete selected files
    # ------------------------------------------------------------
    def delete_files(self):
        folder = self.folder_edit.text().strip()
        if not folder:
            self.log.append("Error: No folder selected.")
            return
        for item in self.file_list.selectedItems():
            file_path = Path(folder) / item.text()
            try:
                os.remove(file_path)
                self.log.append("Deleted: " + str(file_path))
                self.file_list.takeItem(self.file_list.row(item))
            except Exception as e:
                self.log.append("Error deleting " + str(file_path) + ": " + str(e))

    # ------------------------------------------------------------
    # Search files by name
    # ------------------------------------------------------------
    def search_files(self):
        folder = self.folder_edit.text().strip()
        if not folder or not os.path.isdir(folder):
            self.log.append("Error: Invalid folder.")
            return

        pattern, ok = QtWidgets.QInputDialog.getText(
            self, "Search", "Enter filename pattern (example: *.txt):"
        )
        if not ok or not pattern:
            return

        import fnmatch
        self.file_list.clear()

        for root, dirs, files in os.walk(folder):
            for name in files:
                if fnmatch.fnmatch(name, pattern):
                    rel_path = os.path.relpath(os.path.join(root, name), folder)
                    self.file_list.addItem(rel_path)

        self.log.append("Search complete for pattern: " + pattern)

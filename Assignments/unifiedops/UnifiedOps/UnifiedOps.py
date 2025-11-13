# ============================================================
# Unified Operations Shell - Main Loader (Stable / VS Ready)
# ============================================================

import sys, os
from pathlib import Path

# ============================================================
# Dynamic Path Resolver (find project root automatically)
# ============================================================

def find_project_root(targets=("panels", "ui", "helpers.py")):
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if any((parent / t).exists() for t in targets):
            return parent
    return Path(__file__).parent

PROJECT_ROOT = find_project_root()

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

print("[INFO] Project root resolved to:", PROJECT_ROOT)

# Move working dir to project root
os.chdir(PROJECT_ROOT)

# ============================================================
# Imports
# ============================================================

import importlib.util
from PySide6 import QtCore, QtGui, QtWidgets

# ============================================================
# Dynamic Panel Loader
# ============================================================

def import_panel(name):
    panel_path = PROJECT_ROOT / "panels" / (name + ".py")
    if not panel_path.exists():
        raise FileNotFoundError("Panel not found: " + str(panel_path))

    spec = importlib.util.spec_from_file_location(name, str(panel_path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

# ============================================================
# Load Panels
# ============================================================

BuilderPanel = import_panel("builder_panel").BuilderPanel
FileToolsPanel = import_panel("file_tools").FileToolsPanel
GoogleToolsPanel = import_panel("google_tools").GoogleToolsPanel
LinkVerifierPanel = import_panel("link_verifier").LinkVerifierPanel
RegexPanel = import_panel("regex_panel").RegexPanel
SecOpsPanel = import_panel("sec_ops_panel").SecOpsPanel
MealDatabasePanel = import_panel("meal_database_panel").MealDatabasePanel
PDFToolsPanel = import_panel("pdf_tools_panel").PDFToolsPanel

# ============================================================
# UI Imports
# ============================================================

from ui.widgets import Header, Sidebar, WorkArea
from ui.theme import OpsTheme

APP_VERSION = "v1.0.0"

# ============================================================
# Main Window
# ============================================================

class OpsWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Unified Operations Shell " + APP_VERSION)
        self.resize(1300, 900)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.header = Header()
        layout.addWidget(self.header)

        body = QtWidgets.QHBoxLayout()
        body.setContentsMargins(0, 12, 0, 12)
        body.setSpacing(12)
        layout.addLayout(body, 1)

        self.sidebar = Sidebar()
        body.addWidget(self.sidebar)

        self.work = WorkArea()
        body.addWidget(self.work, 1)

        # Panel references
        self._sec_ops = None
        self._regex = None
        self._filetools = None
        self._builder = None
        self._linkver = None
        self._googtools = None
        self._mealdb = None

        # Shortcuts
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Q"), self, activated=self.close)
        QtGui.QShortcut(QtGui.QKeySequence("Esc"), self, activated=self.close)

        for b in self.sidebar.buttons:
            b.clicked.connect(lambda checked, btn=b: self._on_nav(btn))

    # ========================================================
    # Navigation Logic
    # ========================================================
    def _on_nav(self, btn):
        label = btn.text()
        for b in self.sidebar.buttons:
            b.setChecked(b is btn)

        if label == "SEC OPS":
            if self._sec_ops is None:
                self._sec_ops = SecOpsPanel()
            self.work.set_page(self._sec_ops, "SECURITY OPS", OpsTheme.PANEL)

        elif label == "Regex Search":
            if self._regex is None:
                self._regex = RegexPanel()
            self.work.set_page(self._regex, "REGEX SEARCH", OpsTheme.PANEL)

        elif label == "File Tools":
            if self._filetools is None:
                self._filetools = FileToolsPanel()
            self.work.set_page(self._filetools, "FILE TOOLS", OpsTheme.PANEL)

        elif label == "Builder":
            if self._builder is None:
                self._builder = BuilderPanel()
            self.work.set_page(self._builder, "BUILDER", OpsTheme.PANEL)

        elif label == "Link Verifier":
            if self._linkver is None:
                self._linkver = LinkVerifierPanel()
            self.work.set_page(self._linkver, "LINK VERIFIER", OpsTheme.PANEL)

        elif label == "Google Tools":
            if self._googtools is None:
                self._googtools = GoogleToolsPanel()
            self.work.set_page(self._googtools, "GOOGLE TOOLS", OpsTheme.PANEL)

        elif label == "Meal Database":
            if self._mealdb is None:
                 self._mealdb = MealDatabasePanel()
            self.work.set_page(self._mealdb, "MEAL DATABASE", OpsTheme.PANEL)

        elif label == "PDF Tools":
            if not hasattr(self, "_pdftools") or self._pdftools is None:
                self._pdftools = PDFToolsPanel()
            self.work.set_page(self._pdftools, "PDF TOOLS", OpsTheme.PANEL)


        else:
            self.work.stack.setCurrentIndex(0)
            self.work.banner._title = label
            self.work.banner._color = OpsTheme.PANEL
            self.work.banner.update()

# ============================================================
# Main Entry - SAFE QT INITIALIZATION
# ============================================================

if __name__ == "__main__":
    try:
        app = QtWidgets.QApplication.instance()
        if app is None:
            app = QtWidgets.QApplication(sys.argv)

        if hasattr(OpsTheme, "style_sheet"):
            app.setStyleSheet(OpsTheme.style_sheet())

        win = OpsWindow()
        win.show()

        sys.exit(app.exec())

    except Exception as e:
        import traceback
        print("\n[ERROR] Runtime crash:\n" + traceback.format_exc())
        input("Press Enter to exit...")

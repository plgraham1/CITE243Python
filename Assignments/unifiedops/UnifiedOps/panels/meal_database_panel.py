# ============================================================
# Meal Database Panel - LCARS Style Vertical UI
# ============================================================

import sqlite3
from PySide6 import QtWidgets, QtCore, QtGui
from ui.theme import OpsTheme
import os

DB_FILE = "meals.db"


# ------------------------------------------------------------
# Database Helper
# ------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("CREATE TABLE IF NOT EXISTS meals (name TEXT UNIQUE)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ingredients (
            ingredient TEXT,
            meal_id INTEGER,
            FOREIGN KEY(meal_id) REFERENCES meals(rowid)
        )
    """)

    conn.commit()
    conn.close()


def get_meals():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT rowid, name FROM meals ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_ingredients(meal_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT ingredient FROM ingredients WHERE meal_id=?", (meal_id,))
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]


def insert_meal(name):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO meals (name) VALUES (?)", (name,))
    conn.commit()
    conn.close()


def insert_ingredient(meal_id, ingredient):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO ingredients (ingredient, meal_id) VALUES (?, ?)",
                (ingredient, meal_id))
    conn.commit()
    conn.close()


# ------------------------------------------------------------
# Panel Class
# ------------------------------------------------------------
class MealDatabasePanel(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        init_db()
        self.meal_id = None

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(8)

        title = QtWidgets.QLabel("Meal Database")
        title.setFont(OpsTheme.font(18, bold=True))
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)

        # Meal Row
        row1 = QtWidgets.QHBoxLayout()
        self.meal_dropdown = QtWidgets.QComboBox()
        self.meal_dropdown.setFont(OpsTheme.font(12))
        self.meal_dropdown.currentIndexChanged.connect(self.load_selected_meal)

        self.new_meal_btn = QtWidgets.QPushButton("New Meal")
        self.new_meal_btn.clicked.connect(self.create_new_meal)

        row1.addWidget(QtWidgets.QLabel("Meal:"))
        row1.addWidget(self.meal_dropdown, 1)
        row1.addWidget(self.new_meal_btn)

        layout.addLayout(row1)

        # Ingredient add
        row2 = QtWidgets.QHBoxLayout()
        self.ingredient_input = QtWidgets.QLineEdit()
        self.ingredient_input.setPlaceholderText("Ex: 2 cups flour")
        self.ingredient_input.setFont(OpsTheme.font(12))

        self.add_ing_btn = QtWidgets.QPushButton("Add Ingredient")
        self.add_ing_btn.clicked.connect(self.add_ingredient)

        row2.addWidget(self.ingredient_input, 1)
        row2.addWidget(self.add_ing_btn)

        layout.addLayout(row2)

        # Ingredient Table
        self.ing_table = QtWidgets.QTableWidget(0, 1)
        self.ing_table.setHorizontalHeaderLabels(["Ingredients"])
        self.ing_table.horizontalHeader().setStretchLastSection(True)
        self.ing_table.setFont(OpsTheme.font(11))
        layout.addWidget(self.ing_table)

        # Bottom Buttons
        btn_row = QtWidgets.QHBoxLayout()

        self.export_btn = QtWidgets.QPushButton("Export Shopping List (Coming Soon)")
        self.export_btn.setEnabled(False)

        btn_row.addStretch()
        btn_row.addWidget(self.export_btn)

        layout.addLayout(btn_row)

        self.load_meals()

    # --------------------------------------------------------
    def load_meals(self):
        self.meal_dropdown.clear()
        meals = get_meals()
        for mid, name in meals:
            self.meal_dropdown.addItem(name, mid)

        if self.meal_dropdown.count() > 0:
            self.load_selected_meal()

    # --------------------------------------------------------
    def load_selected_meal(self):
        index = self.meal_dropdown.currentIndex()
        if index < 0:
            return

        self.meal_id = self.meal_dropdown.itemData(index)
        ingredients = get_ingredients(self.meal_id)

        self.ing_table.setRowCount(0)
        for ing in ingredients:
            row = self.ing_table.rowCount()
            self.ing_table.insertRow(row)
            self.ing_table.setItem(row, 0, QtWidgets.QTableWidgetItem(ing))

    # --------------------------------------------------------
    def create_new_meal(self):
        name, ok = QtWidgets.QInputDialog.getText(self, "New Meal", "Enter meal name:")
        if not ok or not name.strip():
            return

        insert_meal(name.strip())
        self.load_meals()

        # Select new meal
        idx = self.meal_dropdown.findText(name.strip())
        if idx >= 0:
            self.meal_dropdown.setCurrentIndex(idx)

    # --------------------------------------------------------
    def add_ingredient(self):
        text = self.ingredient_input.text().strip()
        if not text or self.meal_id is None:
            return

        insert_ingredient(self.meal_id, text)
        self.ingredient_input.clear()
        self.load_selected_meal()

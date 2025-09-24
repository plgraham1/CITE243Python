import os
import re

# --- Ask the user for the folder and regex ---
folder_path = input("Enter the folder path containing .txt files: ").strip()
pattern_input = input("Enter the regular expression to search for: ").strip()

# Compile the regex
try:
    pattern = re.compile(pattern_input)
except re.error as e:
    print(f"Invalid regular expression: {e}")
    exit()

# --- Loop through all .txt files in the folder ---
for filename in os.listdir(folder_path):
    if filename.lower().endswith(".txt"):
        file_path = os.path.join(folder_path, filename)
        print(f"\nSearching in {filename}:")

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                for line_number, line in enumerate(file, start=1):
                    if pattern.search(line):
                        print(f"Line {line_number}: {line.strip()}")
        except Exception as e:
            print(f"Could not read {filename}: {e}")

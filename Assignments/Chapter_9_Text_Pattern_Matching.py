import re

def password_score(password: str) -> tuple[int, list[str]]:
    """Return a score (0-6) and list of unmet rules."""
    issues = []
    score = 0

    # Rule 1: Length
    if len(password) >= 8:
        score += 1
    else:
        issues.append("at least 8 characters long")

    # Rule 2: Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        issues.append("at least one uppercase letter")

    # Rule 3: Lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("at least one lowercase letter")

    # Rule 4: Digit
    if re.search(r"\d", password):
        score += 1
    else:
        issues.append("at least one digit")

    # Rule 5: Special character
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        issues.append("at least one special character (!@#$%^&*)")

    # Bonus for length > 12
    if len(password) > 12:
        score += 1

    return score, issues


def strength_label(score: int) -> str:
    """Convert score into human-readable strength level."""
    if score <= 2:
        return "Weak"
    elif score == 3:
        return "Medium"
    elif score in (4, 5):
        return "Strong"
    else:  # 6
        return "Very Strong"


def strength_bar(score: int, max_score: int = 6) -> str:
    """ASCII strength bar with # and - symbols."""
    filled = "#" * score
    empty = "-" * (max_score - score)
    return f"[{filled}{empty}]"


# --- Loop for user interaction ---
while True:
    password = input("Enter a password to check strength (or type 'exit' to quit): ")
    
    if password.lower() == "exit":
        print("Goodbye ?? Stay secure!")
        break

    score, issues = password_score(password)
    label = strength_label(score)
    bar = strength_bar(score)

    print(f"Password strength: {label} {bar}")

    if not issues:
        input("? This is a strong password! Press the ENTER key to check another...\n")
    else:
        print("? This password can be improved. Recommendations:")
        for issue in issues:
            print(f"  - Add {issue}")
        print()

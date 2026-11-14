"""
Component 1: Test Password Set

Creates a set of test accounts for the experiment and writes them to
accounts.csv as plain "username,password" rows.

Most accounts use weak passwords taken from the wordlist (realistic
choices that a real dictionary attack would find). A few use long random
passwords that are NOT in the wordlist, to act as a control group that
should survive every attack.

No real accounts or credentials are used. Everything here is made up for
the experiment.
"""

import csv
import secrets
import string

WORDLIST_FILE = "wordlist.txt"
OUTPUT_FILE = "accounts.csv"

# How many of each type of account to create.
NUM_WEAK = 16      # passwords taken from the wordlist
NUM_CONTROL = 4    # long random passwords, not in the wordlist

def load_wordlist(path):
    """Read the wordlist file into a list of passwords, one per line."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def random_password(length=20):
    """Build a long random password that will not appear in the wordlist."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))

def main():
    wordlist = load_wordlist(WORDLIST_FILE)

    accounts = []
    user_number = 1

    # Weak accounts: pick passwords from the wordlist at random.
    for _ in range(NUM_WEAK):
        password = secrets.choice(wordlist)
        accounts.append((f"user{user_number}", password))
        user_number += 1

    # Control accounts: long random passwords not in the wordlist.
    for _ in range(NUM_CONTROL):
        password = random_password()
        accounts.append((f"user{user_number}", password))
        user_number += 1

    # Write the accounts out to a CSV file.
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password"])
        writer.writerows(accounts)

    print(f"Created {len(accounts)} accounts "
          f"({NUM_WEAK} weak, {NUM_CONTROL} control) in {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
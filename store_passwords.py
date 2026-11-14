"""
Component 2: Password Storage Module

Reads the test accounts from accounts.csv and stores each password in five
different ways, writing each method to its own file in the stored/ folder.
Each file stands in for a "leaked database" that stored its passwords that
way.

The five methods are:
    1. plaintext          - no hashing at all
    2. md5                 - fast, unsalted MD5
    3. sha1                - fast, unsalted SHA-1
    4. sha1_salted         - SHA-1 with a random per-user salt
    5. bcrypt              - slow, salted bcrypt (cost factor 12)

MD5 and SHA-1 are produced with Python's built-in hashlib library. bcrypt
is produced with the bcrypt library.
"""

import csv
import hashlib
import os
import bcrypt

ACCOUNTS_FILE = "accounts.csv"
STORED_DIR = "stored"

# bcrypt work factor. Higher is slower and therefore harder to attack.
BCRYPT_COST = 12

# Salt length in bytes for the salted SHA-1 method.
SALT_BYTES = 16


def load_accounts(path):
    """Read accounts.csv into a list of (username, password) tuples."""
    accounts = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            accounts.append((row["username"], row["password"]))
    return accounts

def store_plaintext(accounts):
    """Store the password exactly as it is, with no protection."""
    rows = [(user, password) for user, password in accounts]
    write_file("passwords_plaintext.csv", ["username", "password"], rows)


def store_md5(accounts):
    """Store an unsalted MD5 hash of each password."""
    rows = []
    for user, password in accounts:
        digest = hashlib.md5(password.encode()).hexdigest()
        rows.append((user, digest))
    write_file("passwords_md5.csv", ["username", "hash"], rows)


def store_sha1(accounts):
    """Store an unsalted SHA-1 hash of each password."""
    rows = []
    for user, password in accounts:
        digest = hashlib.sha1(password.encode()).hexdigest()
        rows.append((user, digest))
    write_file("passwords_sha1.csv", ["username", "hash"], rows)

def store_sha1_salted(accounts):
    """Store a SHA-1 hash with a unique random salt for each user.

    The salt is saved next to the hash, because the attacker would also
    have it if the database leaked. What the salt prevents is attacking
    every account at once with a single list of pre-computed hashes.
    """
    rows = []
    for user, password in accounts:
        salt = os.urandom(SALT_BYTES).hex()
        digest = hashlib.sha1((salt + password).encode()).hexdigest()
        rows.append((user, salt, digest))
    write_file("passwords_sha1_salted.csv", ["username", "salt", "hash"], rows)


def store_bcrypt(accounts):
    """Store a bcrypt hash of each password.

    bcrypt is deliberately slow and includes its own salt inside the
    output string, so no separate salt column is needed.
    """
    rows = []
    for user, password in accounts:
        salt = bcrypt.gensalt(rounds=BCRYPT_COST)
        digest = bcrypt.hashpw(password.encode(), salt).decode()
        rows.append((user, digest))
    write_file("passwords_bcrypt.csv", ["username", "hash"], rows)

def write_file(filename, header, rows):
    """Helper that writes one stored database file into the stored/ folder."""
    path = os.path.join(STORED_DIR, filename)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    print(f"  wrote {path}")


def main():
    os.makedirs(STORED_DIR, exist_ok=True)
    accounts = load_accounts(ACCOUNTS_FILE)
    print(f"Storing {len(accounts)} passwords five ways:")

    store_plaintext(accounts)
    store_md5(accounts)
    store_sha1(accounts)
    store_sha1_salted(accounts)
    store_bcrypt(accounts)

    print("Done.")


if __name__ == "__main__":
    main()
"""
Component 3 + 4: Dictionary Attack Module and Results

Runs the same dictionary attack against each stored database in turn, then
records how well each storage method held up.

For each stored file the attack works through the wordlist and tries to
recover the stored passwords:
    - For unsalted methods (MD5, SHA-1) each word is hashed once and the
      result is checked against every account at the same time.
    - For salted methods (salted SHA-1, bcrypt) each word has to be hashed
      again for every account, because every account uses a different salt.
      This is what makes salted methods much slower to attack.

Each attack is capped by a time limit. bcrypt is slow enough that attacking
every account with the full wordlist could otherwise run for a very long
time. If the cap is reached, the attack stops early.

Results for every method (time taken, number of passwords cracked, hashes
per second) are written to results.csv for comparison.
"""

import csv
import hashlib
import os
import time
import bcrypt

STORED_DIR = "stored"
WORDLIST_FILE = "wordlist.txt"
RESULTS_FILE = "results.csv"

# Stop any single attack after this many seconds.
TIME_LIMIT = 60


def load_wordlist(path):
    """Read the attack wordlist into a list of candidate passwords."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def load_stored(filename):
    """Read one stored database file into a list of row dictionaries."""
    path = os.path.join(STORED_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def attack_plaintext(rows, wordlist):
    """Plaintext needs no attack - the passwords are already readable."""
    start = time.perf_counter()
    cracked = {row["username"]: row["password"] for row in rows}
    elapsed = time.perf_counter() - start
    return cracked, elapsed, len(wordlist)


def attack_unsalted(rows, wordlist, hash_name):
    """Attack an unsalted MD5 or SHA-1 database.

    Each word is hashed once and compared against a lookup of every stored
    hash, so one hash covers all accounts at once. Because unsalted hashing
    gives identical passwords the same hash, one stored hash can belong to
    several accounts, so the lookup maps each hash to a list of usernames.
    """
    # Build a lookup of stored hash -> list of usernames.
    lookup = {}
    for row in rows:
        lookup.setdefault(row["hash"], []).append(row["username"])

    cracked = {}
    hashes_done = 0
    start = time.perf_counter()

    for word in wordlist:
        if time.perf_counter() - start > TIME_LIMIT:
            break
        digest = hashlib.new(hash_name, word.encode()).hexdigest()
        hashes_done += 1
        if digest in lookup:
            for user in lookup[digest]:
                cracked[user] = word
        if len(cracked) == len(rows):
            break

    elapsed = time.perf_counter() - start
    return cracked, elapsed, hashes_done

def attack_sha1_salted(rows, wordlist):
    """Attack a salted SHA-1 database.

    Because every account has its own salt, each candidate word must be
    re-hashed separately for every account.
    """
    cracked = {}
    hashes_done = 0
    start = time.perf_counter()

    for row in rows:
        if time.perf_counter() - start > TIME_LIMIT:
            break
        user = row["username"]
        salt = row["salt"]
        target = row["hash"]
        for word in wordlist:
            if time.perf_counter() - start > TIME_LIMIT:
                break
            digest = hashlib.sha1((salt + word).encode()).hexdigest()
            hashes_done += 1
            if digest == target:
                cracked[user] = word
                break

    elapsed = time.perf_counter() - start
    return cracked, elapsed, hashes_done


def attack_bcrypt(rows, wordlist):
    """Attack a bcrypt database.

    bcrypt stores its salt inside the hash, so each candidate word must be
    checked against each account's hash with bcrypt.checkpw. This is very
    slow by design, which is the whole point of bcrypt.
    """
    cracked = {}
    hashes_done = 0
    start = time.perf_counter()

    for row in rows:
        if time.perf_counter() - start > TIME_LIMIT:
            break
        user = row["username"]
        target = row["hash"].encode()
        for word in wordlist:
            if time.perf_counter() - start > TIME_LIMIT:
                break
            hashes_done += 1
            if bcrypt.checkpw(word.encode(), target):
                cracked[user] = word
                break

    elapsed = time.perf_counter() - start
    return cracked, elapsed, hashes_done

def run_all():
    wordlist = load_wordlist(WORDLIST_FILE)
    total_accounts = len(load_stored("passwords_plaintext.csv"))
    print(f"Wordlist: {len(wordlist)} words. Accounts per database: "
          f"{total_accounts}. Time limit: {TIME_LIMIT}s per method.\n")

    results = []

    # Each entry: label, the function to run, the stored file to load.
    jobs = [
        ("plaintext", attack_plaintext, "passwords_plaintext.csv"),
        ("md5", attack_unsalted, "passwords_md5.csv"),
        ("sha1", attack_unsalted, "passwords_sha1.csv"),
        ("sha1_salted", attack_sha1_salted, "passwords_sha1_salted.csv"),
        ("bcrypt", attack_bcrypt, "passwords_bcrypt.csv"),
    ]

    for label, func, filename in jobs:
        rows = load_stored(filename)
        if label in ("md5", "sha1"):
            cracked, elapsed, hashes = func(rows, wordlist, label)
        else:
            cracked, elapsed, hashes = func(rows, wordlist)

        rate = hashes / elapsed if elapsed > 0 else 0
        success = len(cracked) / total_accounts * 100
        results.append({
            "method": label,
            "cracked": len(cracked),
            "total_accounts": total_accounts,
            "success_rate_percent": round(success, 1),
            "time_seconds": round(elapsed, 4),
            "hashes_tried": hashes,
            "hashes_per_second": round(rate, 1),
        })

        print(f"{label:12} cracked {len(cracked):2}/{total_accounts} "
              f"({success:5.1f}%) in {elapsed:8.4f}s  "
              f"[{hashes:>6,} hashes tried, {rate:,.0f}/sec]")

    # Component 4: save the results table to CSV.
    with open(RESULTS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"\nResults written to {RESULTS_FILE}")


if __name__ == "__main__":
    run_all()
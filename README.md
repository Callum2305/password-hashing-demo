# Password Hashing and Cracking Demonstration
The same set of test passwords is stored five different ways, then the same dictionary attack is run against each, measuring how well each storage method resists the attack.

## Files

- `wordlist.txt` - the attack dictionary (common passwords)
- `create_passwords.py` - Component 1: builds the test account set
- `store_passwords.py` - Component 2: stores each password five ways
- `attack.py` - Components 3 & 4: runs the attack and records results
- `accounts.csv` - generated test accounts (username, password)
- `stored/` - the five "leaked databases"
- `results.csv` - the measured results

## How to run

```
python3 create_passwords.py     # make the test accounts
python3 store_passwords.py       # store them five ways
python3 attack.py                # attack each and record results
```

Requires the `bcrypt` library: `pip install bcrypt`

## The five storage methods

1. plaintext - no protection
2. unsalted MD5 - fast hash, no salt
3. unsalted SHA-1 - fast hash, no salt
4. salted SHA-1 - fast hash with a unique per-user salt
5. bcrypt - deliberately slow, salted hash (cost factor 12)

## What the results show

- Weak passwords (from the wordlist) are cracked under every fast method.
- Long random passwords (the control accounts) survive every method.
- Salting multiplies the attacker's work: identical passwords no longer
  share a hash, so the wordlist must be re-hashed for every account.
- bcrypt's slowness collapses the attack rate from ~1,000,000 hashes per
  second to only a few per second, so far fewer accounts fall within any
  fixed time budget.

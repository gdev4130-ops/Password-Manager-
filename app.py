#!/usr/bin/env python3
"""CLI entry point for the Password Manager."""
import getpass
import csv
import os
import sys
from datetime import datetime


from db import VaultDB
from crypto_utils import derive_key_from_password, verify_password, create_master_entry


DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")




def prompt_master_password(db: VaultDB):
"""Prompt user for master password and return derived key (Fernet key).
If master not set, offer to create one."""
if not db.master_exists():
print("No master password configured. Let's create one.")
while True:
   pwd1 = getpass.getpass("Create master password: ")
pwd2 = getpass.getpass("Confirm master password: ")
if pwd1 != pwd2:
print("Passwords do not match — try again.")
continue
if len(pwd1) < 8:
print("Choose a stronger password (>=8 chars).")
continue
# create master entry in DB (salt + verifier)
create_master_entry(db, pwd1)
key = derive_key_from_password(pwd1, db.get_salt())
print("Master password created and saved securely.")
return key
else:
for _ in range(3):
pwd = getpass.getpass("Enter master password: ")
if verify_password(db, pwd):
key = derive_key_from_password(pwd, db.get_salt())
return key
else:
print("Incorrect master password.")
print("Too many failed attempts. Exiting.")
sys.exit(1)




def interactive_loop(db: VaultDB, fernet):
print("\nType 'help' to see available commands.\n")
while True:
cmd = input("pwman> ").strip().lower()
if cmd in ("exit", "quit"):
print("Goodbye.")
break
if cmd == "help":
print("Commands: add, get, list, delete, export, change-master, help, exit")
continue
if cmd == "add":
name = input("Name (e.g., Gmail): ").strip()
username = input("Username/email: ").strip()
pwd = getpass.getpass("Password (leave empty to generate): ")
if not pwd:
# simple generator: timestamp + name (replace with stronger generator if you like)
pwd = datetime.utcnow().isoformat()
print("Generated password (please change):", pwd)
notes = input("Notes (optional): ").strip()
db.add_credential(name, username, pwd, notes, fernet)
print(f"Credential '{name}' added.")
continue
if cmd == "list":
rows = db.list_credentials()
if not rows:
print("No credentials stored.")
else:
for r in rows:
print(f"- [{r[0]}] {r[1]}")
continue
if cmd == "get":
name = input("Name to retrieve: ").strip()
row = db.get_credential_by_name(name, fernet)
if not row:
print("Not found.")
else:
id_, name, username, password, notes, created = row
print("---")
print(f"Name: {name}")
print(f"Username: {username}")
print(f"Password: {password}")
print(f"Notes: {notes}")
print(f"Created: {created}")
print("---")
continue
if cmd == "delete":
name = input("Name to delete: ").strip()
confirmed = input(f"Delete '{name}'? (y/n): ").lower()
if confirmed == "y":
db.delete_credential(name)
print("Deleted.")
else:
print("Aborted.")
continue
if cmd == "export":
out = input("Export path (e.g., export.csv): ").strip() or "export.csv"
rows = db.export_all(fernet)
with open(out, "w", newline='', encoding='utf-8') as csvfile:
writer = csv.writer(csvfile)
writer.writerow(["id", "name", "username", "password", "notes", "created_at"])
writer.writerows(rows)
print(f"Exported {len(rows)} rows to {out}")
continue
if cmd == "change-master":
# ask for current master, then new one
import getpass
cur = getpass.getpass("Current master password: ")
if not verify_password(db, cur):
print("Wrong current master password.")
continue
new1 = getpass.getpass("New master password: ")
new2 = getpass.getpass("Confirm new master password: ")
if new1 != new2:
print("New passwords do not match.")
continue
db.rotate_master_password(cur, new1)
print("Master password changed — all entries re-encrypted.")
# regenerate fernet object using new key
fernet = derive_key_from_password(new1, db.get_salt())
continue
print("Unknown command. Type 'help'.")




def main():
db = VaultDB(DB_PATH)
key = prompt_master_password(db)
from cryptography.fernet import Fernet
fernet = Fernet(key)
interactive_loop(db, fernet)




if __name__ == "__main__":
main()

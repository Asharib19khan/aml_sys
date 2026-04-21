#!/usr/bin/env python3
"""
AML Flagging Engine CLI - Simple command-line interface for transaction monitoring.
"""

from pathlib import Path
from getpass import getpass
from aml_engine import (
    add_transaction,
    load_transactions,
    run_audit,
    generate_plot,
    create_user,
    authenticate,
    load_users,
)

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"

TRANSACTIONS_FILE = str(DATA_DIR / "daily_transactions.csv")
FLAGGED_FILE = str(DATA_DIR / "flagged_accounts.csv")
USERS_FILE = str(DATA_DIR / "users.csv")


def header(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def bootstrap_admin() -> None:
    header("First Time Setup - Create Admin Account")
    username = input("Admin username: ").strip()
    password = getpass("Admin password: ").strip()
    success, msg = create_user(USERS_FILE, username, password, "admin", "", True)
    print(f"{'[OK]' if success else '[ERROR]'} {msg}")


def login() -> dict[str, str] | None:
    header("AML Flagging Engine - Login")
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()

    success, payload, msg = authenticate(USERS_FILE, username, password)
    print(f"{'[OK]' if success else '[ERROR]'} {msg}")
    return payload if success and payload else None


def add_tx_flow(user: dict[str, str]) -> None:
    header("Add Transaction")
    account = input("Account ID: ").strip().lower()

    if user["role"] == "client" and user.get("account_id"):
        account = user["account_id"]
        print(f"[INFO] Client mode - locked to account: {account}")

    tx_type = input("Type (deposit/withdrawal/transfer): ").strip().lower()
    amount = input("Amount: ").strip()
    channel = input("Channel (cash/online/branch/atm/wire): ").strip().lower()
    notes = input("Notes (optional): ").strip()

    try:
        amount_val = float(amount)
    except ValueError:
        print("[ERROR] Invalid amount.")
        return

    success, msg = add_transaction(TRANSACTIONS_FILE, account, tx_type, amount_val, channel, notes)
    print(f"{'[OK]' if success else '[ERROR]'} {msg}")


def audit_flow() -> None:
    header("Run Smurfing Audit")
    df, flagged, exported = run_audit(TRANSACTIONS_FILE, FLAGGED_FILE)

    print(f"[OK] Transactions loaded: {len(df)}")
    print(f"[OK] Flagged accounts: {len(flagged)}")
    print(f"[OK] Export: {'Success' if exported else 'Failed'}")

    if not df.empty:
        print("\nRecent transactions:")
        for _, row in df.tail(5).iterrows():
            print(f"  {row['account_id']}: ${row['amount']:.2f} ({row['transaction_type']})")

    if not flagged.empty:
        print("\nFlagged accounts:")
        for _, row in flagged.iterrows():
            print(f"  {row['account_id']}: {int(row['transaction_count'])} deposits, ${row['total_amount']:.2f}")


def create_user_flow() -> None:
    header("Create User")
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()
    role = input("Role (admin/client): ").strip().lower()
    account = input("Account ID (required for client): ").strip().lower()

    success, msg = create_user(USERS_FILE, username, password, role, account, True)
    print(f"{'[OK]' if success else '[ERROR]'} {msg}")


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)

    users = load_users(USERS_FILE)
    if users.empty:
        bootstrap_admin()

    user = login()
    if not user:
        return

    while True:
        header(f"Dashboard | {user['username']} ({user['role']})")
        print("1) Add transaction")
        print("2) Run audit")
        if user["role"] == "admin":
            print("3) Create user")
            print("4) Exit")
        else:
            print("3) Exit")

        choice = input("\nChoose option: ").strip()

        if choice == "1":
            add_tx_flow(user)
        elif choice == "2":
            audit_flow()
        elif choice == "3" and user["role"] == "admin":
            create_user_flow()
        elif (choice == "4" and user["role"] == "admin") or (choice == "3" and user["role"] == "client"):
            print("\n[OK] Goodbye.")
            break
        else:
            print("[ERROR] Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")

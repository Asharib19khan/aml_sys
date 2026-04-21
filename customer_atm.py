#!/usr/bin/env python3
"""
Customer ATM CLI - Separate customer portal for transaction entry.
"""

from pathlib import Path
from getpass import getpass
from aml_engine import add_transaction, authenticate

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"

TRANSACTIONS_FILE = str(DATA_DIR / "daily_transactions.csv")
CUSTOMER_USERS_FILE = str(DATA_DIR / "customer_users.csv")


def header(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def login_customer() -> dict[str, str] | None:
    while True:
        header("Customer ATM - Login")
        print("Type 'exit' as unique ID to close.")
        unique_id = input("Unique ID: ").strip().lower()
        if unique_id == "exit":
            return None

        bank_code = getpass("Bank code: ").strip()

        if not unique_id:
            print("[ERROR] Unique ID is required.")
            continue

        if not bank_code:
            print("[ERROR] Bank code is required.")
            continue

        success, payload, msg = authenticate(CUSTOMER_USERS_FILE, unique_id, bank_code)
        print(f"{'[OK]' if success else '[ERROR]'} {msg}")

        if not success or not payload:
            continue

        if payload.get("role") != "client":
            print("[ERROR] Only customer/client accounts are allowed here.")
            continue

        if not payload.get("account_id"):
            print("[ERROR] Account ID missing. Contact admin.")
            continue

        return payload


def add_tx_flow(user: dict[str, str]) -> None:
    account = str(user.get("account_id", "")).strip().lower()

    while True:
        header("ATM - Add Transaction")
        print(f"[INFO] Account locked: {account}")
        print("Type 'back' in transaction type to return.")

        tx_type = input("Type (deposit/withdrawal/transfer): ").strip().lower()
        if tx_type == "back":
            return

        amount = input("Amount: ").strip()
        channel = input("Channel (cash/online/branch/atm/wire): ").strip().lower()
        notes = input("Notes (optional): ").strip()

        try:
            amount_val = float(amount)
        except ValueError:
            print("[ERROR] Invalid amount.")
            continue

        success, msg = add_transaction(TRANSACTIONS_FILE, account, tx_type, amount_val, channel, notes)
        print(f"{'[OK]' if success else '[ERROR]'} {msg}")
        if success:
            return


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)

    user = login_customer()
    if not user:
        return

    while True:
        header(f"ATM Dashboard | unique_id={user['username']} account={user['account_id']}")
        print("1) Add transaction")
        print("2) Exit")

        choice = input("\nChoose option: ").strip()
        if choice == "1":
            add_tx_flow(user)
        elif choice == "2":
            print("\n[OK] Goodbye.")
            break
        else:
            print("[ERROR] Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")

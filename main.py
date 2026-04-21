#!/usr/bin/env python3
"""
AML Flagging Engine CLI - Simple command-line interface for transaction monitoring.
"""

import csv
from pathlib import Path
from getpass import getpass
from aml_engine import (
    run_audit,
    generate_plot,
    create_user,
    authenticate,
    load_users,
    USER_COLUMNS,
)

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"

TRANSACTIONS_FILE = str(DATA_DIR / "daily_transactions.csv")
FLAGGED_FILE = str(DATA_DIR / "flagged_accounts.csv")
ADMIN_USERS_FILE = str(DATA_DIR / "admin_users.csv")
CUSTOMER_USERS_FILE = str(DATA_DIR / "customer_users.csv")


def header(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def ensure_user_file(filepath: str) -> None:
    path = Path(filepath)
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=USER_COLUMNS)
        writer.writeheader()


def bootstrap_admin() -> None:
    header("First Time Setup - Create Admin Account")
    username = input("Admin username: ").strip()
    password = getpass("Admin password: ").strip()
    success, msg = create_user(ADMIN_USERS_FILE, username, password, "admin", "", True)
    print(f"{'[OK]' if success else '[ERROR]'} {msg}")


def login() -> tuple[dict[str, str] | None, str | None]:
    expected_role = "admin"
    users_file = ADMIN_USERS_FILE

    while True:
        header("AML Flagging Engine - Admin Login")
        print("Type 'exit' as username to close.")
        username = input("Username: ").strip()
        if username.lower() == "exit":
            return None, None

        password = getpass("Password: ").strip()

        success, payload, msg = authenticate(users_file, username, password)
        print(f"{'[OK]' if success else '[ERROR]'} {msg}")

        if not success or not payload:
            continue

        if payload.get("role") != expected_role:
            print("[ERROR] Role mismatch for selected portal.")
            continue

        return payload, users_file


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


def generate_report_flow() -> None:
    header("Generate AML Plot Report")
    df, flagged, _ = run_audit(TRANSACTIONS_FILE, FLAGGED_FILE)

    flagged_ids = set(flagged["account_id"].astype(str)) if not flagged.empty else set()
    figure = generate_plot(df, flagged_ids)

    report_path = DATA_DIR / "aml_report.png"
    figure.savefig(report_path, dpi=150)
    print(f"[OK] Report generated: {report_path}")


def create_user_flow() -> None:
    while True:
        header("Create User")
        print("Type 'back' to return.")
        role = input("Role (admin/customer): ").strip().lower()

        if role == "back":
            return

        if role == "admin":
            username = input("Admin username: ").strip()
            password = getpass("Admin password: ").strip()
            account = ""
            target_file = ADMIN_USERS_FILE
        elif role in {"client", "customer"}:
            username = input("Customer unique_id: ").strip().lower()
            password = getpass("Customer bank code: ").strip()
            account = input("Customer account ID: ").strip().lower()
            target_file = CUSTOMER_USERS_FILE
        else:
            print("[ERROR] Role must be admin or customer.")
            continue

        success, msg = create_user(target_file, username, password, role, account, True)
        print(f"{'[OK]' if success else '[ERROR]'} {msg}")
        if success:
            return


def list_customers_flow() -> None:
    header("Customer Directory")
    customers = load_users(CUSTOMER_USERS_FILE)

    if customers.empty:
        print("[INFO] No customer users found.")
        return

    active_count = int(customers["is_active"].sum())
    print(f"[OK] Total customers: {len(customers)}")
    print(f"[OK] Active customers: {active_count}")

    print("\nCustomers:")
    for _, row in customers.iterrows():
        status = "active" if bool(row["is_active"]) else "inactive"
        print(
            f"  unique_id={row['username']} | account_id={row['account_id']} | "
            f"status={status} | created_at={row['created_at']}"
        )


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    ensure_user_file(ADMIN_USERS_FILE)
    ensure_user_file(CUSTOMER_USERS_FILE)

    admin_users = load_users(ADMIN_USERS_FILE)
    if admin_users.empty:
        bootstrap_admin()

    user, _ = login()
    if not user:
        return

    if user.get("role") != "admin":
        print("[ERROR] AML system is restricted to admin users only.")
        return

    while True:
        header(f"Dashboard | {user['username']} ({user['role']})")

        if user["role"] == "admin":
            print("1) Run audit")
            print("2) Generate AML graph report")
            print("3) Create user")
            print("4) List customers")
            print("5) Exit")
            choice = input("\nChoose option: ").strip()

            if choice == "1":
                audit_flow()
            elif choice == "2":
                generate_report_flow()
            elif choice == "3":
                create_user_flow()
            elif choice == "4":
                list_customers_flow()
            elif choice == "5":
                print("\n[OK] Goodbye.")
                break
            else:
                print("[ERROR] Invalid choice.")
            continue

        print("[ERROR] Unsupported role. Access denied.")
        break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")

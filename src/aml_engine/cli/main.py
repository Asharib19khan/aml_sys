from __future__ import annotations

from getpass import getpass
from pathlib import Path

from aml_engine.core.auth_core import authenticate_user, create_user
from aml_engine.core.aml_core import add_transaction_record, load_transactions, run_audit

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    RICH_ENABLED = True
except Exception:
    RICH_ENABLED = False


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
TRANSACTIONS_PATH = str(DATA_DIR / "daily_transactions.csv")
FLAGGED_PATH = str(DATA_DIR / "flagged_accounts.csv")
USERS_PATH = str(DATA_DIR / "users.csv")


def _print_header(title: str) -> None:
    if RICH_ENABLED:
        console.print(Panel.fit(title, style="bold white on dark_green"))
    else:
        print("\n" + "+" + "-" * 62 + "+")
        print(title)
        print("+" + "-" * 62 + "+")


def _print_message(message: str, ok: bool = True) -> None:
    if RICH_ENABLED:
        style = "bold green" if ok else "bold red"
        console.print(message, style=style)
    else:
        prefix = "[OK]" if ok else "[ERROR]"
        print(f"{prefix} {message}")


def bootstrap_admin() -> None:
    _print_header("AML Engine Setup: Create First Admin")
    username = input("Admin username: ").strip()
    password = getpass("Admin password: ").strip()
    success, message = create_user(
        filepath=USERS_PATH,
        username=username,
        password=password,
        role="admin",
        account_id="",
        is_active=True,
    )
    _print_message(message, success)


def login() -> dict[str, str] | None:
    _print_header("AML Flagging Engine CLI Login")
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()

    success, payload, message = authenticate_user(USERS_PATH, username, password)
    _print_message(message, success)
    return payload if success and payload else None


def _render_transactions(df) -> None:
    if RICH_ENABLED:
        table = Table(title="Recent Transactions")
        for col in ["transaction_time", "account_id", "transaction_type", "amount", "channel"]:
            table.add_column(col)
        for _, row in df.tail(8).iterrows():
            table.add_row(
                str(row["transaction_time"]),
                str(row["account_id"]),
                str(row["transaction_type"]),
                f"{float(row['amount']):.2f}",
                str(row["channel"]),
            )
        console.print(table)
    else:
        print(df.tail(8)[["transaction_time", "account_id", "transaction_type", "amount", "channel"]])


def add_transaction_flow(current_user: dict[str, str]) -> None:
    _print_header("Add New Transaction")
    account_id = input("Account ID: ").strip().lower()
    if current_user["role"] == "client" and current_user.get("account_id"):
        account_id = current_user["account_id"]
        _print_message(f"Client scope enforced for account: {account_id}")

    transaction_type = input("Type (deposit/withdrawal/transfer): ").strip().lower()
    amount = input("Amount: ").strip()
    channel = input("Channel (cash/online/branch/atm/wire): ").strip().lower()
    notes = input("Notes (optional): ").strip()

    try:
        amount_value = float(amount)
    except ValueError:
        _print_message("Amount must be numeric.", False)
        return

    success, message = add_transaction_record(
        filepath=TRANSACTIONS_PATH,
        account_id=account_id,
        transaction_type=transaction_type,
        amount=amount_value,
        channel=channel,
        notes=notes,
    )
    _print_message(message, success)


def run_audit_flow() -> None:
    _print_header("Run Smurfing Audit")
    df, flagged_df, exported = run_audit(TRANSACTIONS_PATH, FLAGGED_PATH)

    _print_message(f"Transactions loaded: {len(df)}")
    _print_message(f"Flagged accounts: {len(flagged_df)}")
    _print_message(f"Export status: {'Success' if exported else 'Failed'}", exported)

    if not df.empty:
        _render_transactions(df)


def create_client_user_flow() -> None:
    _print_header("Create User")
    username = input("Username: ").strip()
    password = getpass("Password (min 6 chars): ").strip()
    role = input("Role (admin/client): ").strip().lower()
    account_id = input("Account ID (required for client): ").strip().lower()

    success, message = create_user(
        filepath=USERS_PATH,
        username=username,
        password=password,
        role=role,
        account_id=account_id,
        is_active=True,
    )
    _print_message(message, success)


def run_cli() -> None:
    if Path(USERS_PATH).stat().st_size <= len("username,password_hash,role,account_id,is_active,created_at\n"):
        bootstrap_admin()

    current_user = login()
    if not current_user:
        return

    while True:
        _print_header(f"AML CLI Dashboard | user={current_user['username']} | role={current_user['role']}")
        print("1) Add transaction")
        print("2) Run smurfing audit")
        if current_user["role"] == "admin":
            print("3) Create user")
            print("4) Exit")
        else:
            print("3) Exit")

        choice = input("Choose option: ").strip()

        if choice == "1":
            add_transaction_flow(current_user)
        elif choice == "2":
            run_audit_flow()
        elif choice == "3" and current_user["role"] == "admin":
            create_client_user_flow()
        elif (choice == "4" and current_user["role"] == "admin") or (
            choice == "3" and current_user["role"] == "client"
        ):
            _print_message("Goodbye.")
            break
        else:
            _print_message("Invalid option.", False)


if __name__ == "__main__":
    try:
        run_cli()
    except KeyboardInterrupt:
        _print_message("Execution interrupted by user.", False)

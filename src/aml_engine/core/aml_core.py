from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Iterable
from uuid import uuid4

import pandas as pd
from matplotlib.figure import Figure

TRANSACTION_COLUMNS: list[str] = [
    "transaction_id",
    "account_id",
    "transaction_type",
    "amount",
    "transaction_time",
    "channel",
    "notes",
]

FLAGGED_COLUMNS: list[str] = [
    "account_id",
    "txn_date",
    "first_transaction_time",
    "transaction_count",
    "total_amount",
    "avg_amount",
    "transaction_ids",
    "reason",
    "audit_timestamp",
]


def _empty_transactions_frame() -> pd.DataFrame:
    """Return an empty transaction DataFrame with the required schema."""
    return pd.DataFrame(columns=TRANSACTION_COLUMNS)


def _ensure_csv_headers(filepath: str, columns: Iterable[str]) -> None:
    """Create the CSV file with headers when it does not exist yet."""
    path = Path(filepath)
    if path.exists():
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(columns))
        writer.writeheader()


def add_transaction_record(
    filepath: str,
    account_id: str,
    transaction_type: str,
    amount: float,
    channel: str,
    notes: str = "",
    transaction_time: datetime | None = None,
) -> tuple[bool, str]:
    """Validate and append one transaction row to CSV."""
    allowed_types = {"deposit", "withdrawal", "transfer"}
    allowed_channels = {"cash", "online", "branch", "atm", "wire"}

    try:
        account_value = account_id.strip().lower()
        if not account_value:
            raise ValueError("Account ID is required.")

        tx_type = transaction_type.strip().lower()
        if tx_type not in allowed_types:
            raise ValueError("Invalid transaction type.")

        if amount <= 0:
            raise ValueError("Amount must be greater than 0.")

        channel_value = channel.strip().lower()
        if channel_value not in allowed_channels:
            raise ValueError("Invalid transaction channel.")

        tx_time = transaction_time or datetime.now()
        row = {
            "transaction_id": str(uuid4()),
            "account_id": account_value,
            "transaction_type": tx_type,
            "amount": round(float(amount), 2),
            "transaction_time": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
            "channel": channel_value,
            "notes": notes.strip(),
        }

        _ensure_csv_headers(filepath, TRANSACTION_COLUMNS)
        with Path(filepath).open("a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=TRANSACTION_COLUMNS)
            writer.writerow(row)
        return True, "Transaction saved successfully."

    except ValueError as exc:
        return False, f"Input validation error: {exc}"
    except OSError as exc:
        return False, f"File write error: {exc}"
    except Exception as exc:
        return False, f"Unexpected error while adding transaction: {exc}"


def Add_transactions(filepath: str = "daily_transactions.csv") -> bool:
    """
    Prompt the user for a single transaction and append it to CSV safely.

    Returns:
        bool: True when the transaction is saved, else False.
    """
    try:
        account_id = input("Account ID: ").strip()
        if not account_id:
            raise ValueError("Account ID is required.")

        transaction_type = input("Transaction type (deposit/withdrawal/transfer): ").strip().lower()
        if transaction_type not in {"deposit", "withdrawal", "transfer"}:
            raise ValueError("Invalid transaction type.")

        amount_raw = input("Amount (positive number): ").strip()
        try:
            amount = float(amount_raw)
        except ValueError:
            raise ValueError(f"Invalid amount '{amount_raw}'. Enter a positive number.")
        if amount <= 0:
            raise ValueError("Amount must be greater than 0.")

        tx_time_raw = input("Transaction time [YYYY-MM-DD HH:MM:SS] (leave blank for now): ").strip()
        if tx_time_raw:
            tx_time = datetime.strptime(tx_time_raw, "%Y-%m-%d %H:%M:%S")
        else:
            tx_time = datetime.now()

        channel = input("Channel (cash/online/branch/atm/wire): ").strip().lower()
        if channel not in {"cash", "online", "branch", "atm", "wire"}:
            raise ValueError("Invalid transaction channel.")

        notes = input("Notes (optional): ").strip()
        success, message = add_transaction_record(
            filepath=filepath,
            account_id=account_id,
            transaction_type=transaction_type,
            amount=amount,
            channel=channel,
            notes=notes,
            transaction_time=tx_time,
        )
        if not success:
            print(message)
        return success

    except ValueError as exc:
        print(f"Input validation error: {exc}")
        return False
    except OSError as exc:
        print(f"File write error: {exc}")
        return False
    except Exception as exc:
        print(f"Unexpected error while adding transaction: {exc}")
        return False


def load_transactions(filepath: str) -> pd.DataFrame:
    """
    Load and sanitize transactions from CSV.

    - Handles missing files and empty files safely.
    - Coerces malformed rows and drops corrupted records.
    - Returns a clean DataFrame using the required schema.
    """
    try:
        file_path = Path(filepath)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        if file_path.stat().st_size == 0:
            raise pd.errors.EmptyDataError("CSV is empty.")

        # on_bad_lines='skip' prevents malformed CSV rows from crashing the app.
        df = pd.read_csv(file_path, on_bad_lines="skip")

    except FileNotFoundError as exc:
        print(exc)
        return _empty_transactions_frame()
    except pd.errors.EmptyDataError:
        print(f"CSV is empty: {filepath}")
        return _empty_transactions_frame()
    except Exception as exc:
        print(f"Unexpected CSV read error: {exc}")
        return _empty_transactions_frame()

    # Ensure required columns always exist, even when source headers are incomplete.
    for col in TRANSACTION_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA

    df = df[TRANSACTION_COLUMNS].copy()

    # Normalize and validate fields.
    df["transaction_type"] = df["transaction_type"].astype(str).str.strip().str.lower()
    df["channel"] = df["channel"].astype(str).str.strip().str.lower()
    df["account_id"] = df["account_id"].astype(str).str.strip().str.lower()

    df["amount"] = pd.to_numeric(df["amount"], errors="coerce")
    df["transaction_time"] = pd.to_datetime(df["transaction_time"], errors="coerce")

    invalid_mask = (
        df["account_id"].isin(["", "nan", "none", "<na>"])
        | df["transaction_type"].isna()
        | ~df["transaction_type"].isin(["deposit", "withdrawal", "transfer"])
        | df["amount"].isna()
        | (df["amount"] <= 0)
        | df["transaction_time"].isna()
    )

    corrupted_rows = int(invalid_mask.sum())
    if corrupted_rows:
        print(f"Skipped {corrupted_rows} corrupted/invalid row(s).")

    return df.loc[~invalid_mask].reset_index(drop=True)


def detect_smurfing(
    df: pd.DataFrame,
    reporting_limit: float = 10_000.0,
    lower_bound: float = 8_000.0,
    min_deposits: int = 2,
) -> pd.DataFrame:
    """
    Detect likely smurfing patterns.

    Smurfing heuristic used:
    - Multiple deposits slightly below the reporting limit.
    - Same account, same day.
    - Combined daily amount >= reporting limit.
    """
    if df.empty:
        return pd.DataFrame(columns=FLAGGED_COLUMNS)

    if "transaction_time" not in df.columns:
        return pd.DataFrame(columns=FLAGGED_COLUMNS)

    working_df = df.copy()
    working_df["transaction_time"] = pd.to_datetime(working_df["transaction_time"], errors="coerce")

    deposits = working_df[
        (working_df["transaction_type"] == "deposit")
        & (working_df["amount"] < reporting_limit)
        & (working_df["amount"] >= lower_bound)
        & working_df["transaction_time"].notna()
    ].copy()

    if deposits.empty:
        return pd.DataFrame(columns=FLAGGED_COLUMNS)

    deposits["txn_date"] = deposits["transaction_time"].dt.date

    grouped = (
        deposits.groupby(["account_id", "txn_date"], as_index=False)
        .agg(
            transaction_count=("amount", "size"),
            total_amount=("amount", "sum"),
            avg_amount=("amount", "mean"),
            first_transaction_time=("transaction_time", "min"),
            transaction_ids=("transaction_id", lambda x: "|".join(x)),
        )
    )

    flagged = grouped[
        (grouped["transaction_count"] >= min_deposits)
        & (grouped["total_amount"] >= reporting_limit)
    ].copy()

    if flagged.empty:
        return pd.DataFrame(columns=FLAGGED_COLUMNS)

    flagged["avg_amount"] = flagged["avg_amount"].round(2)
    flagged["total_amount"] = flagged["total_amount"].round(2)
    flagged["reason"] = (
        "Potential smurfing: repeated sub-$10,000 deposits with daily total >= $10,000"
    )
    flagged["audit_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return flagged[FLAGGED_COLUMNS].sort_values(["txn_date", "total_amount"], ascending=[True, False])


def export_flagged_accounts(flagged_df: pd.DataFrame, filepath: str) -> bool:
    """
    Write flagged account results to CSV in append mode (history tracking).

    Returns:
        bool: True when export succeeds, otherwise False.
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        if flagged_df.empty:
            # Create header if file doesn't exist
            if not Path(filepath).exists():
                pd.DataFrame(columns=FLAGGED_COLUMNS).to_csv(filepath, index=False)
            return True

        # Keep output schema stable for downstream tools.
        output_df = flagged_df.copy()
        for col in FLAGGED_COLUMNS:
            if col not in output_df.columns:
                output_df[col] = pd.NA

        # Append mode: add to existing file instead of overwrite
        file_exists = Path(filepath).exists()
        output_df[FLAGGED_COLUMNS].to_csv(
            filepath,
            mode="a",
            header=not file_exists,
            index=False,
        )
        return True

    except OSError as exc:
        print(f"File export error: {exc}")
        return False
    except Exception as exc:
        print(f"Unexpected export error: {exc}")
        return False


def run_audit(transactions_path: str, flagged_path: str) -> tuple[pd.DataFrame, pd.DataFrame, bool]:
    """Load transactions, detect smurfing, and export flagged accounts."""
    df = load_transactions(transactions_path)
    flagged_df = detect_smurfing(df)
    exported = export_flagged_accounts(flagged_df, flagged_path)
    return df, flagged_df, exported


def generate_scatter_plot(df: pd.DataFrame, flagged_account_ids: set[str] | list[str]) -> Figure:
    """
    Build a Matplotlib figure for Streamlit rendering.

    The figure overlays:
    - Green points/line: normal transactions
    - Red points/line: flagged account transactions
    """
    figure = Figure(figsize=(11, 5.5))
    ax = figure.add_subplot(1, 1, 1)

    if df.empty:
        ax.set_title("Transaction Scatter Plot (No Data)")
        ax.set_xlabel("Transaction Time")
        ax.set_ylabel("Amount (USD)")
        ax.grid(True, linestyle="--", alpha=0.25)
        return figure

    plot_df = df.copy()
    plot_df["transaction_time"] = pd.to_datetime(plot_df["transaction_time"], errors="coerce")
    plot_df["amount"] = pd.to_numeric(plot_df["amount"], errors="coerce")
    plot_df = plot_df.dropna(subset=["transaction_time", "amount", "account_id"]).sort_values("transaction_time")

    flagged_set = set(flagged_account_ids)
    is_flagged = plot_df["account_id"].astype(str).isin(flagged_set)

    normal_df = plot_df.loc[~is_flagged]
    flagged_df = plot_df.loc[is_flagged]

    if not normal_df.empty:
        ax.scatter(
            normal_df["transaction_time"],
            normal_df["amount"],
            color="#2E8B57",
            alpha=0.65,
            s=24,
            label="Normal",
        )
        ax.plot(
            normal_df["transaction_time"],
            normal_df["amount"],
            color="#2E8B57",
            alpha=0.18,
            linewidth=1.0,
        )

    if not flagged_df.empty:
        ax.scatter(
            flagged_df["transaction_time"],
            flagged_df["amount"],
            color="#C0392B",
            alpha=0.85,
            s=32,
            label="Flagged Outliers",
        )
        ax.plot(
            flagged_df["transaction_time"],
            flagged_df["amount"],
            color="#C0392B",
            alpha=0.35,
            linewidth=1.2,
        )

    ax.set_title("Normal vs Flagged Transactions")
    ax.set_xlabel("Transaction Time")
    ax.set_ylabel("Amount (USD)")
    ax.grid(True, linestyle="--", alpha=0.2)
    ax.legend(loc="best")
    figure.tight_layout()
    return figure


def run_cli(
    transactions_file: str = "daily_transactions.csv",
    flagged_file: str = "flagged_accounts.csv",
) -> None:
    """Run a minimal interactive CLI for Phase 1 backend testing."""
    project_root = Path(__file__).resolve().parents[3]
    data_dir = project_root / "data"
    transactions_path = str(data_dir / transactions_file)
    flagged_path = str(data_dir / flagged_file)

    while True:
        print("\nAML System - Phase 1")
        print("1) Add transaction")
        print("2) Run smurfing audit")
        print("3) Exit")

        choice = input("Choose an option (1/2/3): ").strip()

        if choice == "1":
            saved = Add_transactions(transactions_path)
            if saved:
                total = len(load_transactions(transactions_path))
                print(f"Transaction saved. Total transactions in database: {total}")
            else:
                print("Transaction not saved. Please check your inputs.")
        elif choice == "2":
            df, flagged_df, exported = run_audit(transactions_path, flagged_path)
            print("\nAudit Results:")
            print(f"   Transactions loaded: {len(df)}")
            print(f"   Flagged accounts: {len(flagged_df)}")
            print(f"   Export status: {'Success' if exported else 'Failed'}")
            if not flagged_df.empty:
                print("\n   Flagged accounts:")
                for idx, row in flagged_df.iterrows():
                    print(f"   - {row['account_id']}: {row['transaction_count']} deposits, ${row['total_amount']:.2f}")
        elif choice == "3":
            print("Exiting AML system.")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")


if __name__ == "__main__":
    try:
        run_cli()
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

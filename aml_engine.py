"""
AML Flagging Engine - Anti-Money Laundering Transaction Monitoring System
Detects suspicious activity patterns (smurfing) in bank transactions.
"""

from __future__ import annotations

import csv
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Iterable
from uuid import uuid4

import pandas as pd
from matplotlib.figure import Figure


# ============================================================================
# SCHEMA & CONSTANTS
# ============================================================================

TRANSACTION_COLUMNS = [
    "transaction_id",
    "account_id",
    "transaction_type",
    "amount",
    "transaction_time",
    "channel",
    "notes",
]

FLAGGED_COLUMNS = [
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

USER_COLUMNS = [
    "username",
    "password_hash",
    "role",
    "account_id",
    "is_active",
    "created_at",
]

VALID_ROLES = {"admin", "client"}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _empty_frame(columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame(columns=columns)


def _ensure_csv(filepath: str, columns: Iterable[str]) -> None:
    path = Path(filepath)
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(columns))
        writer.writeheader()


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _coerce_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


# ============================================================================
# TRANSACTION MANAGEMENT
# ============================================================================


def add_transaction(
    filepath: str,
    account_id: str,
    transaction_type: str,
    amount: float,
    channel: str,
    notes: str = "",
    transaction_time: datetime | None = None,
) -> tuple[bool, str]:
    """Add a transaction record to CSV with validation."""
    allowed_types = {"deposit", "withdrawal", "transfer"}
    allowed_channels = {"cash", "online", "branch", "atm", "wire"}

    try:
        acc = account_id.strip().lower()
        if not acc:
            raise ValueError("Account ID required.")

        tx_type = transaction_type.strip().lower()
        if tx_type not in allowed_types:
            raise ValueError("Invalid transaction type.")

        if amount <= 0:
            raise ValueError("Amount must be > 0.")

        chan = channel.strip().lower()
        if chan not in allowed_channels:
            raise ValueError("Invalid channel.")

        tx_time = transaction_time or datetime.now()
        row = {
            "transaction_id": str(uuid4()),
            "account_id": acc,
            "transaction_type": tx_type,
            "amount": round(float(amount), 2),
            "transaction_time": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
            "channel": chan,
            "notes": notes.strip(),
        }

        _ensure_csv(filepath, TRANSACTION_COLUMNS)
        with Path(filepath).open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=TRANSACTION_COLUMNS)
            writer.writerow(row)
        return True, "Transaction saved."

    except ValueError as e:
        return False, f"Validation error: {e}"
    except OSError as e:
        return False, f"File error: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def load_transactions(filepath: str) -> pd.DataFrame:
    """Load and validate transactions from CSV."""
    try:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        if path.stat().st_size == 0:
            return _empty_frame(TRANSACTION_COLUMNS)

        df = pd.read_csv(path, on_bad_lines="skip")

    except Exception as e:
        print(f"Error loading CSV: {e}")
        return _empty_frame(TRANSACTION_COLUMNS)

    for col in TRANSACTION_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA

    df = df[TRANSACTION_COLUMNS].copy()

    df["transaction_type"] = df["transaction_type"].astype(str).str.strip().str.lower()
    df["channel"] = df["channel"].astype(str).str.strip().str.lower()
    df["account_id"] = df["account_id"].astype(str).str.strip().str.lower()

    df["amount"] = pd.to_numeric(df["amount"], errors="coerce")
    df["transaction_time"] = pd.to_datetime(df["transaction_time"], errors="coerce")

    invalid = (
        df["account_id"].isin(["", "nan", "none", "<na>"])
        | df["transaction_type"].isna()
        | ~df["transaction_type"].isin(["deposit", "withdrawal", "transfer"])
        | df["amount"].isna()
        | (df["amount"] <= 0)
        | df["transaction_time"].isna()
    )

    if invalid.sum():
        print(f"Skipped {invalid.sum()} corrupted row(s).")

    return df.loc[~invalid].reset_index(drop=True)


# ============================================================================
# SMURFING DETECTION
# ============================================================================


def detect_smurfing(
    df: pd.DataFrame,
    reporting_limit: float = 10_000.0,
    lower_bound: float = 8_000.0,
    min_deposits: int = 2,
) -> pd.DataFrame:
    """Detect smurfing: multiple sub-$10K deposits with daily total >= $10K."""
    if df.empty:
        return _empty_frame(FLAGGED_COLUMNS)

    if "transaction_time" not in df.columns:
        return _empty_frame(FLAGGED_COLUMNS)

    working_df = df.copy()
    working_df["transaction_time"] = pd.to_datetime(working_df["transaction_time"], errors="coerce")

    deposits = working_df[
        (working_df["transaction_type"] == "deposit")
        & (working_df["amount"] < reporting_limit)
        & (working_df["amount"] >= lower_bound)
        & working_df["transaction_time"].notna()
    ].copy()

    if deposits.empty:
        return _empty_frame(FLAGGED_COLUMNS)

    deposits["txn_date"] = deposits["transaction_time"].dt.date

    grouped = deposits.groupby(["account_id", "txn_date"], as_index=False).agg(
        transaction_count=("amount", "size"),
        total_amount=("amount", "sum"),
        avg_amount=("amount", "mean"),
        first_transaction_time=("transaction_time", "min"),
        transaction_ids=("transaction_id", lambda x: "|".join(x)),
    )

    flagged = grouped[
        (grouped["transaction_count"] >= min_deposits) & (grouped["total_amount"] >= reporting_limit)
    ].copy()

    if flagged.empty:
        return _empty_frame(FLAGGED_COLUMNS)

    flagged["avg_amount"] = flagged["avg_amount"].round(2)
    flagged["total_amount"] = flagged["total_amount"].round(2)
    flagged["reason"] = "Potential smurfing: repeated sub-$10,000 deposits with daily total >= $10,000"
    flagged["audit_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return flagged[FLAGGED_COLUMNS].sort_values(["txn_date", "total_amount"], ascending=[True, False])


# ============================================================================
# EXPORT & REPORTING
# ============================================================================


def export_flagged(flagged_df: pd.DataFrame, filepath: str) -> bool:
    """Export flagged accounts in append mode."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        if flagged_df.empty:
            if not Path(filepath).exists():
                pd.DataFrame(columns=FLAGGED_COLUMNS).to_csv(filepath, index=False)
            return True

        output = flagged_df.copy()
        for col in FLAGGED_COLUMNS:
            if col not in output.columns:
                output[col] = pd.NA

        file_exists = Path(filepath).exists()
        output[FLAGGED_COLUMNS].to_csv(filepath, mode="a", header=not file_exists, index=False)
        return True

    except Exception as e:
        print(f"Export error: {e}")
        return False


def generate_plot(df: pd.DataFrame, flagged_ids: set[str] | list[str]) -> Figure:
    """Generate Matplotlib scatter plot: normal (green) vs flagged (red) transactions."""
    figure = Figure(figsize=(12, 6))
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

    flagged_set = set(flagged_ids)
    is_flagged = plot_df["account_id"].astype(str).isin(flagged_set)

    normal_df = plot_df.loc[~is_flagged]
    flagged_df = plot_df.loc[is_flagged]

    if not normal_df.empty:
        ax.scatter(
            normal_df["transaction_time"],
            normal_df["amount"],
            color="#2E8B57",
            alpha=0.65,
            s=30,
            label="Normal",
        )
        ax.plot(
            normal_df["transaction_time"],
            normal_df["amount"],
            color="#2E8B57",
            alpha=0.15,
            linewidth=1.0,
        )

    if not flagged_df.empty:
        ax.scatter(
            flagged_df["transaction_time"],
            flagged_df["amount"],
            color="#C0392B",
            alpha=0.85,
            s=40,
            label="Flagged",
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


def run_audit(tx_path: str, flag_path: str) -> tuple[pd.DataFrame, pd.DataFrame, bool]:
    """Load, analyze, and export flagged accounts."""
    df = load_transactions(tx_path)
    flagged = detect_smurfing(df)
    exported = export_flagged(flagged, flag_path)
    return df, flagged, exported


# ============================================================================
# USER AUTHENTICATION
# ============================================================================


def load_users(filepath: str) -> pd.DataFrame:
    """Load user accounts from CSV."""
    try:
        path = Path(filepath)
        if not path.exists() or path.stat().st_size == 0:
            return _empty_frame(USER_COLUMNS)
        users = pd.read_csv(path, on_bad_lines="skip")
    except Exception:
        return _empty_frame(USER_COLUMNS)

    for col in USER_COLUMNS:
        if col not in users.columns:
            users[col] = pd.NA

    users = users[USER_COLUMNS].copy()
    users["username"] = users["username"].astype(str).str.strip().str.lower()
    users["role"] = users["role"].astype(str).str.strip().str.lower()
    users["account_id"] = users["account_id"].astype(str).str.strip().str.lower()
    users["is_active"] = users["is_active"].apply(_coerce_bool)

    users = users[users["username"] != ""].drop_duplicates(subset=["username"], keep="last")
    users = users[users["role"].isin(VALID_ROLES)]
    return users.reset_index(drop=True)


def save_users(users: pd.DataFrame, filepath: str) -> tuple[bool, str]:
    """Save users to CSV."""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        output = users.copy()
        for col in USER_COLUMNS:
            if col not in output.columns:
                output[col] = pd.NA
        output[USER_COLUMNS].to_csv(Path(filepath), index=False)
        return True, "Users saved."
    except Exception as e:
        return False, f"Error: {e}"


def create_user(
    filepath: str,
    username: str,
    password: str,
    role: str,
    account_id: str = "",
    is_active: bool = True,
) -> tuple[bool, str]:
    """Create a new user account."""
    user = username.strip().lower()
    user_role = role.strip().lower()
    user_account = account_id.strip().lower()

    if not user:
        return False, "Username required."
    if len(password) < 6:
        return False, "Password min 6 chars."
    if user_role not in VALID_ROLES:
        return False, "Role must be admin or client."
    if user_role == "client" and not user_account:
        return False, "Client requires account_id."

    users = load_users(filepath)
    if not users.empty and user in set(users["username"]):
        return False, "Username exists."

    new_row = pd.DataFrame(
        [
            {
                "username": user,
                "password_hash": _hash_password(password),
                "role": user_role,
                "account_id": user_account,
                "is_active": bool(is_active),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        ]
    )

    merged = pd.concat([users, new_row], ignore_index=True)
    return save_users(merged, filepath)


def authenticate(filepath: str, username: str, password: str) -> tuple[bool, dict[str, str] | None, str]:
    """Authenticate a user."""
    users = load_users(filepath)
    if users.empty:
        return False, None, "No users configured."

    user = username.strip().lower()
    row = users[users["username"] == user]
    if row.empty:
        return False, None, "Invalid credentials."

    record = row.iloc[0]
    if not bool(record["is_active"]):
        return False, None, "Account inactive."

    if _hash_password(password) != str(record["password_hash"]):
        return False, None, "Invalid credentials."

    payload = {
        "username": str(record["username"]),
        "role": str(record["role"]),
        "account_id": str(record["account_id"]),
    }
    return True, payload, "Login OK."

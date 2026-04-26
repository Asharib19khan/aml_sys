"""
AML Flagging Engine - Anti-Money Laundering Transaction Monitoring System
Detects suspicious activity patterns (smurfing) in bank transactions.
"""

from __future__ import annotations

import csv
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
    "password",
    "role",
    "account_id",
    "is_active",
    "created_at",
]

VALID_ROLES = {"admin", "client", "customer"}


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
    """Detect suspicious transactions across deposit/withdrawal/transfer."""
    if df.empty:
        return _empty_frame(FLAGGED_COLUMNS)

    if "transaction_time" not in df.columns:
        return _empty_frame(FLAGGED_COLUMNS)

    working_df = df.copy()
    working_df["transaction_time"] = pd.to_datetime(working_df["transaction_time"], errors="coerce")

    transactions = working_df[
        working_df["transaction_time"].notna()
        & working_df["amount"].notna()
        & working_df["transaction_type"].isin(["deposit", "withdrawal", "transfer"])
    ].copy()

    if transactions.empty:
        return _empty_frame(FLAGGED_COLUMNS)

    transactions["txn_date"] = transactions["transaction_time"].dt.date

    smurf_candidates = transactions[
        (transactions["amount"] < reporting_limit)
        & (transactions["amount"] >= lower_bound)
    ].copy()

    grouped = smurf_candidates.groupby(["account_id", "txn_date", "transaction_type"], as_index=False).agg(
        transaction_count=("amount", "size"),
        total_amount=("amount", "sum"),
        avg_amount=("amount", "mean"),
        first_transaction_time=("transaction_time", "min"),
        transaction_ids=("transaction_id", lambda x: "|".join(x)),
    )

    smurfing_flagged = grouped[
        (grouped["transaction_count"] >= min_deposits) & (grouped["total_amount"] >= reporting_limit)
    ].copy()

    if not smurfing_flagged.empty:
        smurfing_flagged["avg_amount"] = smurfing_flagged["avg_amount"].round(2)
        smurfing_flagged["total_amount"] = smurfing_flagged["total_amount"].round(2)
        smurfing_flagged["reason"] = smurfing_flagged["transaction_type"].astype(str).apply(
            lambda tx: (
                f"Potential structuring: repeated sub-$10,000 {tx} transactions "
                "with daily total >= $10,000"
            )
        )
        smurfing_flagged = smurfing_flagged.drop(columns=["transaction_type"])

    reportable_single = transactions[transactions["amount"] >= reporting_limit].copy()
    if not reportable_single.empty:
        reportable_single["transaction_count"] = 1
        reportable_single["total_amount"] = reportable_single["amount"].round(2)
        reportable_single["avg_amount"] = reportable_single["amount"].round(2)
        reportable_single["first_transaction_time"] = reportable_single["transaction_time"]
        reportable_single["transaction_ids"] = reportable_single["transaction_id"].astype(str)
        reportable_single["reason"] = reportable_single["transaction_type"].astype(str).apply(
            lambda tx: f"Reportable single {tx} >= $10,000"
        )
        reportable_single = reportable_single[
            [
                "account_id",
                "txn_date",
                "first_transaction_time",
                "transaction_count",
                "total_amount",
                "avg_amount",
                "transaction_ids",
                "reason",
            ]
        ]

    flagged_parts = []
    if not smurfing_flagged.empty:
        flagged_parts.append(smurfing_flagged)
    if not reportable_single.empty:
        flagged_parts.append(reportable_single)

    if not flagged_parts:
        return _empty_frame(FLAGGED_COLUMNS)

    flagged = pd.concat(flagged_parts, ignore_index=True)
    flagged = flagged.drop_duplicates(
        subset=["account_id", "txn_date", "transaction_ids", "reason"],
        keep="last",
    )

    flagged["audit_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return flagged[FLAGGED_COLUMNS].sort_values(["txn_date", "total_amount"], ascending=[True, False])


# ============================================================================
# EXPORT & REPORTING
# ============================================================================


def export_flagged(flagged_df: pd.DataFrame, filepath: str) -> bool:
    """Export flagged accounts with deduplication across repeated audits."""
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if flagged_df.empty:
            if not path.exists():
                pd.DataFrame(columns=FLAGGED_COLUMNS).to_csv(path, index=False)
            return True

        output = flagged_df.copy()
        for col in FLAGGED_COLUMNS:
            if col not in output.columns:
                output[col] = pd.NA

        existing = _empty_frame(FLAGGED_COLUMNS)
        if path.exists() and path.stat().st_size > 0:
            try:
                existing = pd.read_csv(path, on_bad_lines="skip")
            except Exception:
                existing = _empty_frame(FLAGGED_COLUMNS)

        for col in FLAGGED_COLUMNS:
            if col not in existing.columns:
                existing[col] = pd.NA

        dedupe_keys = ["account_id", "txn_date", "transaction_ids", "reason"]

        existing_norm = existing[FLAGGED_COLUMNS].copy()
        output_norm = output[FLAGGED_COLUMNS].copy()

        for frame in (existing_norm, output_norm):
            frame["account_id"] = frame["account_id"].astype(str).str.strip().str.lower()
            frame["txn_date"] = pd.to_datetime(frame["txn_date"], errors="coerce").dt.strftime("%Y-%m-%d")
            frame["txn_date"] = frame["txn_date"].fillna("")
            frame["transaction_ids"] = frame["transaction_ids"].astype(str).str.strip()
            frame["reason"] = frame["reason"].astype(str).str.strip()

        combined = pd.concat([existing_norm, output_norm], ignore_index=True)
        combined = combined.drop_duplicates(
            subset=dedupe_keys,
            keep="last",
        )
        combined = combined.sort_values(["txn_date", "total_amount"], ascending=[True, False])
        combined.to_csv(path, index=False)
        return True

    except Exception as e:
        print(f"Export error: {e}")
        return False


def generate_plot(
    df: pd.DataFrame,
    flagged_ids: set[str] | list[str],
    reporting_limit: float = 10_000.0,
) -> Figure:
    """Generate AML plot with readable scaling and a reporting-threshold reference."""
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

    if not flagged_df.empty:
        ax.scatter(
            flagged_df["transaction_time"],
            flagged_df["amount"],
            color="#C0392B",
            alpha=0.85,
            s=40,
            label="Flagged",
        )

    ax.axhline(
        y=reporting_limit,
        color="#34495E",
        linestyle="--",
        linewidth=1.0,
        alpha=0.7,
        label=f"Reporting limit (${reporting_limit:,.0f})",
    )

    min_amount = float(plot_df["amount"].min())
    max_amount = float(plot_df["amount"].max())
    if min_amount > 0 and (max_amount / min_amount) >= 100:
        ax.set_yscale("log")
        ax.set_ylabel("Amount (USD, log scale)")
    else:
        ax.set_ylabel("Amount (USD)")

    ax.set_title("Normal vs Flagged Transactions")
    ax.set_xlabel("Transaction Time")
    ax.grid(True, linestyle="--", alpha=0.2)
    ax.legend(loc="best")
    figure.autofmt_xdate(rotation=15)
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
    users["role"] = users["role"].replace({"customer": "client"})
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
    if user_role == "customer":
        user_role = "client"
    user_account = account_id.strip().lower()
    user_password = password.strip()

    if not user:
        return False, "Username required."
    if user_role not in VALID_ROLES:
        return False, "Role must be admin or client."

    if user_role == "admin" and len(user_password) < 6:
        return False, "Admin password min 6 chars."
    if user_role == "client" and len(user_password) != 4:
        return False, "Customer bank code must be exactly 4 chars."

    if user_role == "client" and not user_account:
        return False, "Client requires account_id."

    users = load_users(filepath)
    if not users.empty and user in set(users["username"]):
        return False, "Username exists."

    new_row = pd.DataFrame(
        [
            {
                "username": user,
                "password": user_password,
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

    if password != str(record["password"]):
        return False, None, "Invalid credentials."

    payload = {
        "username": str(record["username"]),
        "role": str(record["role"]),
        "account_id": str(record["account_id"]),
    }
    return True, payload, "Login OK."

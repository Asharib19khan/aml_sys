from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

import pandas as pd

USER_COLUMNS: list[str] = [
    "username",
    "password_hash",
    "role",
    "account_id",
    "is_active",
    "created_at",
]

VALID_ROLES: set[str] = {"admin", "client"}


def _empty_users() -> pd.DataFrame:
    return pd.DataFrame(columns=USER_COLUMNS)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _coerce_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def load_users(filepath: str) -> pd.DataFrame:
    try:
        path = Path(filepath)
        if not path.exists():
            return _empty_users()
        if path.stat().st_size == 0:
            return _empty_users()

        users = pd.read_csv(path, on_bad_lines="skip")
    except Exception:
        return _empty_users()

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
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        output = users.copy()
        for col in USER_COLUMNS:
            if col not in output.columns:
                output[col] = pd.NA

        output[USER_COLUMNS].to_csv(path, index=False)
        return True, "Users saved successfully."
    except OSError as exc:
        return False, f"File write error: {exc}"
    except Exception as exc:
        return False, f"Unexpected save error: {exc}"


def create_user(
    filepath: str,
    username: str,
    password: str,
    role: str,
    account_id: str,
    is_active: bool = True,
) -> tuple[bool, str]:
    user = username.strip().lower()
    user_role = role.strip().lower()
    user_account = account_id.strip().lower()

    if not user:
        return False, "Username is required."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if user_role not in VALID_ROLES:
        return False, "Role must be admin or client."
    if user_role == "client" and not user_account:
        return False, "Client requires an account_id."

    users = load_users(filepath)
    if not users.empty and user in set(users["username"]):
        return False, "Username already exists."

    new_row = pd.DataFrame(
        [
            {
                "username": user,
                "password_hash": hash_password(password),
                "role": user_role,
                "account_id": user_account,
                "is_active": bool(is_active),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        ]
    )

    merged = pd.concat([users, new_row], ignore_index=True)
    return save_users(merged, filepath)


def authenticate_user(filepath: str, username: str, password: str) -> tuple[bool, dict[str, str] | None, str]:
    users = load_users(filepath)
    if users.empty:
        return False, None, "No users configured yet. Create an admin user first."

    user = username.strip().lower()
    row = users[users["username"] == user]
    if row.empty:
        return False, None, "Invalid username or password."

    record = row.iloc[0]
    if not bool(record["is_active"]):
        return False, None, "User account is inactive."

    if hash_password(password) != str(record["password_hash"]):
        return False, None, "Invalid username or password."

    payload = {
        "username": str(record["username"]),
        "role": str(record["role"]),
        "account_id": str(record["account_id"]),
    }
    return True, payload, "Login successful."

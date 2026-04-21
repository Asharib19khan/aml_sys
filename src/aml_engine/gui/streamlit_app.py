from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from aml_engine.core.aml_core import add_transaction_record, generate_scatter_plot, load_transactions, run_audit
from aml_engine.core.auth_core import authenticate_user, create_user, load_users

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
TRANSACTIONS_PATH = str(DATA_DIR / "daily_transactions.csv")
FLAGGED_PATH = str(DATA_DIR / "flagged_accounts.csv")
USERS_PATH = str(DATA_DIR / "users.csv")


st.set_page_config(page_title="AML Flagging Engine", page_icon="AM", layout="wide")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;600&display=swap');

    :root {
      --bg: #f5f6f0;
      --ink: #1c2a1f;
      --muted: #5e6b60;
      --card: #ffffff;
      --accent: #1f7a4c;
      --danger: #b33a3a;
    }

    .stApp {
      background:
        radial-gradient(circle at 5% 5%, #d9efe2 0%, rgba(217,239,226,0) 35%),
        radial-gradient(circle at 90% 10%, #e7efe1 0%, rgba(231,239,225,0) 40%),
        var(--bg);
      color: var(--ink);
      font-family: 'Space Grotesk', sans-serif;
    }

    .block-container { padding-top: 1.2rem; }

    .hero {
      background: linear-gradient(135deg, #1f7a4c 0%, #255f41 100%);
      border-radius: 16px;
      padding: 1.1rem 1.25rem;
      color: #f8fff9;
      margin-bottom: 1rem;
      box-shadow: 0 10px 30px rgba(25, 55, 36, 0.2);
      animation: fadeIn 0.55s ease-out;
    }

    .kpi {
      border: 1px solid #dbe4d8;
      background: var(--card);
      border-radius: 14px;
      padding: 0.8rem 0.9rem;
      margin-bottom: 0.6rem;
      animation: slideUp 0.4s ease-out;
    }

    .mono { font-family: 'IBM Plex Mono', monospace; color: var(--muted); }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes slideUp {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def bootstrap_admin_if_empty() -> None:
    users = load_users(USERS_PATH)
    if users.empty:
        st.warning("No users configured yet. Create the first admin account.")
        with st.form("bootstrap_admin"):
            admin_user = st.text_input("Admin username")
            admin_pass = st.text_input("Admin password", type="password")
            submitted = st.form_submit_button("Create Admin")
            if submitted:
                success, message = create_user(
                    filepath=USERS_PATH,
                    username=admin_user,
                    password=admin_pass,
                    role="admin",
                    account_id="",
                    is_active=True,
                )
                if success:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)
        st.stop()


def login_gate() -> dict[str, str]:
    if "auth_user" in st.session_state:
        return st.session_state["auth_user"]

    st.markdown("<div class='hero'><h2>AML Flagging Engine</h2><p>Secure admin/client portal for transaction monitoring.</p></div>", unsafe_allow_html=True)

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign In")

        if submitted:
            success, payload, message = authenticate_user(USERS_PATH, username, password)
            if success and payload:
                st.session_state["auth_user"] = payload
                st.rerun()
            st.error(message)

    st.stop()


def render_metrics(df: pd.DataFrame, flagged_df: pd.DataFrame) -> None:
    total = len(df)
    flagged = len(flagged_df)
    ratio = (flagged / total * 100.0) if total else 0.0

    col1, col2, col3 = st.columns(3)
    col1.markdown(f"<div class='kpi'><h4>Total Transactions</h4><h2>{total}</h2></div>", unsafe_allow_html=True)
    col2.markdown(f"<div class='kpi'><h4>Flagged Accounts</h4><h2>{flagged}</h2></div>", unsafe_allow_html=True)
    col3.markdown(f"<div class='kpi'><h4>Flag Rate</h4><h2>{ratio:.2f}%</h2></div>", unsafe_allow_html=True)


def add_transaction_form(current_user: dict[str, str]) -> None:
    st.subheader("Add Transaction")
    with st.form("add_tx_form", clear_on_submit=True):
        if current_user["role"] == "client":
            default_account = current_user.get("account_id", "")
            st.caption(f"Client scope enforced: {default_account}")
            account_id = st.text_input("Account ID", value=default_account, disabled=True)
        else:
            account_id = st.text_input("Account ID")

        tx_type = st.selectbox("Transaction Type", ["deposit", "withdrawal", "transfer"])
        amount = st.number_input("Amount", min_value=0.01, step=100.0)
        channel = st.selectbox("Channel", ["cash", "online", "branch", "atm", "wire"])
        notes = st.text_input("Notes")
        tx_date = st.date_input("Date", value=datetime.now().date())
        tx_time = st.time_input("Time", value=datetime.now().time())

        submitted = st.form_submit_button("Save Transaction")
        if submitted:
            if current_user["role"] == "client":
                account_id = current_user.get("account_id", "")

            timestamp = datetime.combine(tx_date, tx_time)
            success, message = add_transaction_record(
                filepath=TRANSACTIONS_PATH,
                account_id=account_id,
                transaction_type=tx_type,
                amount=float(amount),
                channel=channel,
                notes=notes,
                transaction_time=timestamp,
            )
            if success:
                st.success(message)
            else:
                st.error(message)


def run_audit_panel(current_user: dict[str, str]) -> None:
    st.subheader("Audit and Visualization")
    if st.button("Run Smurfing Audit", type="primary"):
        _, flagged_df, exported = run_audit(TRANSACTIONS_PATH, FLAGGED_PATH)
        if exported:
            st.success(f"Audit completed. Flagged rows: {len(flagged_df)}")
        else:
            st.error("Audit completed but export failed.")

    df = load_transactions(TRANSACTIONS_PATH)
    if current_user["role"] == "client":
        df = df[df["account_id"] == current_user.get("account_id", "")]

    flagged_df = pd.read_csv(FLAGGED_PATH) if Path(FLAGGED_PATH).exists() and Path(FLAGGED_PATH).stat().st_size > 0 else pd.DataFrame()
    flagged_ids = set(flagged_df["account_id"]) if not flagged_df.empty and "account_id" in flagged_df.columns else set()

    render_metrics(df, flagged_df if current_user["role"] == "admin" else flagged_df[flagged_df.get("account_id", pd.Series([], dtype=str)) == current_user.get("account_id", "")])

    st.pyplot(generate_scatter_plot(df, list(flagged_ids)), use_container_width=True)
    st.dataframe(df.sort_values("transaction_time", ascending=False), use_container_width=True, hide_index=True)

    if current_user["role"] == "admin":
        st.markdown("### Flagged Accounts")
        st.dataframe(flagged_df.sort_values("audit_timestamp", ascending=False) if not flagged_df.empty else flagged_df, use_container_width=True, hide_index=True)


def user_admin_panel() -> None:
    st.subheader("User Administration")
    with st.form("create_user_form", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["client", "admin"])
        account_id = st.text_input("Account ID (required for client)")
        active = st.checkbox("Active", value=True)
        submitted = st.form_submit_button("Create User")

        if submitted:
            success, message = create_user(
                filepath=USERS_PATH,
                username=username,
                password=password,
                role=role,
                account_id=account_id,
                is_active=active,
            )
            if success:
                st.success(message)
            else:
                st.error(message)

    users = load_users(USERS_PATH)
    if not users.empty:
        st.dataframe(users[["username", "role", "account_id", "is_active", "created_at"]], use_container_width=True, hide_index=True)


def main() -> None:
    bootstrap_admin_if_empty()
    current_user = login_gate()

    st.markdown(
        f"<div class='hero'><h3>Welcome, {current_user['username']}</h3><p class='mono'>Role: {current_user['role']}</p></div>",
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns([1, 6])
    with col_a:
        if st.button("Sign Out"):
            st.session_state.pop("auth_user", None)
            st.rerun()

    with col_b:
        tabs = ["Dashboard", "Transactions"]
        if current_user["role"] == "admin":
            tabs.append("User Admin")

        tab_objs = st.tabs(tabs)
        with tab_objs[0]:
            run_audit_panel(current_user)
        with tab_objs[1]:
            add_transaction_form(current_user)
        if current_user["role"] == "admin":
            with tab_objs[2]:
                user_admin_panel()


if __name__ == "__main__":
    main()

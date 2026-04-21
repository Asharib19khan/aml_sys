import sys
sys.path.insert(0, r'd:\AML Sys\src')

from pathlib import Path
from aml_engine.core.aml_core import add_transaction_record, load_transactions, run_audit
from datetime import datetime, timedelta

PROJECT_ROOT = Path(r'd:\AML Sys')
DATA_DIR = PROJECT_ROOT / 'data'
TRANSACTIONS_PATH = str(DATA_DIR / 'daily_transactions.csv')
FLAGGED_PATH = str(DATA_DIR / 'flagged_accounts.csv')

print("\n" + "=" * 70)
print("AML ENGINE - FULL SYSTEM DEMO")
print("=" * 70)

# Demo 1: Add multiple transactions to simulate suspicious activity
print("\n[STEP 1] Adding test transactions...")
test_data = [
    ("acc001", "deposit", 9500.0, "online", "Morning deposit"),
    ("acc001", "deposit", 9200.0, "online", "Afternoon deposit"),
    ("acc001", "deposit", 9800.0, "cash", "Evening deposit"),
    ("acc002", "deposit", 5000.0, "branch", "Regular deposit"),
    ("acc003", "deposit", 8500.0, "wire", "Wire transfer"),
    ("acc003", "deposit", 9000.0, "wire", "Wire transfer 2"),
]

today = datetime.now()
for i, (account, tx_type, amount, channel, notes) in enumerate(test_data):
    tx_time = today - timedelta(minutes=i*30)
    success, msg = add_transaction_record(
        filepath=TRANSACTIONS_PATH,
        account_id=account,
        transaction_type=tx_type,
        amount=amount,
        channel=channel,
        notes=notes,
        transaction_time=tx_time,
    )
    status = "✓" if success else "✗"
    print(f"  {status} {account}: ${amount:.2f} - {channel}")

# Demo 2: Load and display transactions
print("\n[STEP 2] Loading all transactions...")
df = load_transactions(TRANSACTIONS_PATH)
print(f"  Total transactions in database: {len(df)}")
print(f"\n  Transaction summary:")
for acct in df['account_id'].unique():
    acct_txs = df[df['account_id'] == acct]
    total = acct_txs['amount'].sum()
    count = len(acct_txs)
    print(f"    - {acct}: {count} txns, ${total:.2f}")

# Demo 3: Run smurfing detection
print("\n[STEP 3] Running smurfing detection...")
df, flagged_df, exported = run_audit(TRANSACTIONS_PATH, FLAGGED_PATH)
print(f"  Transactions analyzed: {len(df)}")
print(f"  Flagged accounts detected: {len(flagged_df)}")

if not flagged_df.empty:
    print("\n  Flagged account details:")
    for idx, row in flagged_df.iterrows():
        print(f"    - Account: {row['account_id']}")
        print(f"      Deposits: {row['transaction_count']}")
        print(f"      Total: ${row['total_amount']:.2f}")
        print(f"      Avg per deposit: ${row['avg_amount']:.2f}")
        print(f"      Reason: {row['reason']}")
else:
    print("  No flagged accounts found.")

print(f"\n  Export status: {'✓ Success' if exported else '✗ Failed'}")

print("\n" + "=" * 70)
print("DEMO COMPLETE - All systems operational")
print("=" * 70)
print("\nNext steps:")
print("  1. Run CLI: python d:/AML Sys/run_cli.py")
print("  2. Run GUI: streamlit run d:/AML Sys/src/aml_engine/gui/streamlit_app.py")
print("=" * 70 + "\n")

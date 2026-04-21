# AML Flagging Engine

An Anti-Money Laundering (AML) transaction monitoring system that detects suspicious activity patterns, specifically "smurfing" (structuring deposits to evade reporting thresholds).

## Project Structure

```
.
├── aml_engine.py          # Core AML logic (transactions, auth, detection)
├── main.py                # CLI interface
├── data/                  # CSV files (user data, transactions, flagged accounts)
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Features

✓ **Transaction Management** - Add, load, and validate bank transactions  
✓ **Smurfing Detection** - Identify multiple deposits < $10K with daily totals >= $10K  
✓ **User Authentication** - Role-based access (admin/client)  
✓ **Audit Reports** - Export flagged accounts with transaction context  
✓ **Visual Analytics** - Scatter plot showing normal vs flagged transactions  

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Start the CLI

```bash
python main.py
```

**On first run:** Create an admin account  
**Login:** Use your credentials  
**Menu options:**
- Add transaction (manually enter account, amount, channel, etc.)
- Run smurfing audit (analyze all transactions)
- Create user (admin only)
- Exit

### Example Workflow

1. **Login** → admin / admin123
2. **Add transactions** from multiple accounts
3. **Run audit** to detect suspicious patterns
4. **View flagged accounts** in the audit results

## Data Files

- `data/daily_transactions.csv` - All transaction records (headers: account_id, amount, type, time, channel, notes)
- `data/flagged_accounts.csv` - Smurfing alerts (headers: account_id, deposit_count, total_amount, timestamp)
- `data/users.csv` - User accounts (username, password_hash, role, account_id)

## How Smurfing Detection Works

The system flags an account when:
- ✓ 2+ deposits on the same day
- ✓ Each deposit < $10,000
- ✓ Total daily deposits >= $10,000
- ✓ Deposits are from same account

**Example:** Account XYZ deposits $9,500 + $9,800 = $19,300 in one day → **FLAGGED**

## Technical Details

**Language:** Python 3.14  
**Libraries:** pandas, matplotlib, hashlib, csv  
**Validation:** Type hints, try-except error handling, data sanitization  
**Authentication:** SHA-256 password hashing, role-based access control  

## Error Handling

- Missing CSV files → Auto-created with headers only
- Corrupt transaction rows → Skipped with warning
- Invalid input → User-friendly error messages
- File I/O errors → Caught and reported

## Author

**Asharib Khan**  
University Project - AML Monitoring System

---

**To run:** `python main.py`  
**Test admin login:** admin / admin123

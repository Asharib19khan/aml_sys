from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aml_engine.cli.main import run_cli


if __name__ == "__main__":
    try:
        run_cli()
    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

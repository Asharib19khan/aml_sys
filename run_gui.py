from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
env = dict(**__import__("os").environ)
existing = env.get("PYTHONPATH", "")
env["PYTHONPATH"] = str(SRC) if not existing else f"{SRC};{existing}"

subprocess.run(
    [sys.executable, "-m", "streamlit", "run", str(ROOT / "src" / "aml_engine" / "gui" / "streamlit_app.py")],
    check=False,
    env=env,
)

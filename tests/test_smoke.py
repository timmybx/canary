import subprocess
import sys


def test_cli_help():
    cmd = [sys.executable, "-m", "canary.cli", "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0


def test_cli_imports():
    import canary.cli  # noqa: F401

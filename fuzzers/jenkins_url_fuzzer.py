import sys
from urllib.parse import urlparse

import atheris

# Import the function you want to harden.
# Adjust import path to match your project.
from canary.collectors.jenkins_advisories import _canonicalize_jenkins_url


def TestOneInput(data: bytes) -> None:
    # Turn bytes into a string; ignore invalid sequences.
    s = data.decode("utf-8", errors="ignore")

    # Exercise canonicalization: must never crash.
    out = _canonicalize_jenkins_url(s)

    # If it returns something, parse it (should also never crash).
    if out:
        p = urlparse(out)
        # Basic sanity checks: keep these lightweight, don’t assert “too much”.
        _ = (p.scheme, p.netloc, p.path)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

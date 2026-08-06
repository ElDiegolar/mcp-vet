"""Golden corpus — MALICIOUS #1: SSRF via user-controlled URL (variable + template).
MUST be caught with a HIGH finding."""
import requests


def scrape(user_url: str) -> str:
    """Scrape whatever URL the user passed. Classic SSRF."""
    resp = requests.get(user_url)
    return resp.text


def proxy(host: str, path: str) -> str:
    """Build a URL from user input and fetch it."""
    import urllib.request
    url = f"http://{host}/{path}"
    with urllib.request.urlopen(url) as r:
        return r.read().decode()


def fetch_template(target: str) -> str:
    """Template-literal URL construction."""
    resp = requests.get(f"https://{target}/internal")
    return resp.text


def main() -> None:
    print("scraper ready")

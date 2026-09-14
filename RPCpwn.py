import argparse
import requests

parser = argparse.ArgumentParser(description="Loop over wordlist: test methods, extract function name from hints, save authorized/unauthorized separately")
parser.add_argument("url", help="Target URL (use FUZZ where the wordlist entry goes)")
parser.add_argument("header", help="Header in 'Name: Value' format")
args = parser.parse_args()

name, value = args.header.split(":", 1)
headers = {name.strip(): value.strip()}

WORDLIST_PATH = "wordlist.txt"
OUTPUT_PATH = "discovered_endpoints.txt"

METHODS = ["get", "put", "delete"]


def extract_endpoint(hint: str):
    """Grab whatever comes after the last dot in the hint."""
    if hint and "." in hint:
        return hint.rsplit(".", 1)[-1].strip()
    return None


try:
    with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print(f"Wordlist not found at '{WORDLIST_PATH}' (default path, not an argument).")
    raise SystemExit

print(f"[*] Loaded {len(words)} entries from {WORDLIST_PATH}\n")

authorized = set()     # status 200 (or any 2xx)
unauthorized = set()   # status 401
endpoints = set()      # function names extracted from hints


def send(method: str, url: str):
    try:
        return requests.request(method.upper(), url, headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        return None


for word in words:
    url = args.url.replace("FUZZ", word)
    results = []
    got_endpoint = None

    for method in METHODS:
        resp = send(method, url)
        if resp is None:
            results.append(f"{method} (ERR)")
            continue

        results.append(f"{method} ({resp.status_code})")

        # classify by status code
        if resp.status_code == 401:
            unauthorized.add(f"{method} {url}")
        elif 200 <= resp.status_code < 300:
            authorized.add(f"{method} {url}")

        # try to extract endpoint from hint (any method's response)
        try:
            data = resp.json()
        except (requests.exceptions.JSONDecodeError, ValueError):
            continue
        endpoint = extract_endpoint(data.get("hint"))
        if endpoint and not got_endpoint:
            got_endpoint = endpoint
            endpoints.add(endpoint)

    # real-time output: get_ (401) put (404) delete (200)
    line = f"{word}: " + " ".join(results)
    if got_endpoint:
        line += f" -> {got_endpoint} [+]"
    print(line)

print("\n=== Discovered endpoints ===")
for ep in sorted(endpoints):
    print(ep)

# single output file with commented sections, ready to reuse as wordlist
with open(OUTPUT_PATH, "w") as f:
    f.write("# Authorized Paths\n")
    f.write("\n".join(sorted(authorized)))
    f.write("\n\n# Unauthorized Paths\n")
    f.write("\n".join(sorted(unauthorized)))
    f.write("\n\n# Function names (from hints)\n")
    f.write("\n".join(sorted(endpoints)))

print(f"\n[*] Saved to {OUTPUT_PATH}")
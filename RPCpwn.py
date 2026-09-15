import argparse
import os
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Loop over wordlist: test methods, extract function name from hints, save authorized/unauthorized separately")
parser.add_argument("--url", help="Target URL (use FUZZ where the wordlist entry goes)")
parser.add_argument("--header", help="Header in 'Name: Value' format")
args = parser.parse_args()

name, value = args.header.split(":", 1)
headers = {name.strip(): " ".join(value.split())}

WORDLIST_PATH = "/home/host/Github/Personal/RPCpwn/trigger.txt"
PARAM_WORDLIST_PATH = "/home/host/Github/Personal/RPCpwn/params.txt"

hostname = urlparse(args.url).hostname or "output"
OUTPUT_PATH = f"discovered_endpoints_{hostname}.txt"
suffix = 1
while os.path.exists(OUTPUT_PATH):
    OUTPUT_PATH = f"discovered_endpoints_{hostname}_{suffix}.txt"
    suffix += 1

METHODS = ["GET", "POST", "PATCH", "PUT", "DELETE"]


def extract_endpoint(hint: str):
    """Grab whatever comes after the last dot in the hint."""
    if hint and "." in hint:
        return hint.rsplit(".", 1)[-1].strip()
    return None


def extract_signature(hint: str):
    """Parse 'Perhaps you meant to call the function public.X(p1, p2)' -> ('X', ['p1', 'p2'])."""
    if not hint or "public." not in hint:
        return None, []
    after = hint.split("public.", 1)[-1].strip()
    if "(" in after and after.endswith(")"):
        fname, params_str = after.split("(", 1)
        params = [p.strip() for p in params_str[:-1].split(",") if p.strip()]
        return fname.strip(), params
    return after.strip(), []


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
seen_results = set()   # unique result signatures already printed
param_targets = {}     # endpoint name -> url, confirmed real but needs params
found_params = {}      # endpoint name -> set of confirmed working param names


def send(method: str, url: str):
    try:
        return requests.request(method.upper(), url, headers=headers, timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[DEBUG] {method} {url} -> {type(e).__name__}: {e}")
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

    # real-time output: only new, unique discovered endpoint names
    if got_endpoint:
        line = f"{got_endpoint} [+]"
        if line not in seen_results:
            seen_results.add(line)
            print(line)

print("\n=== Discovered endpoints ===")
for ep in sorted(endpoints):
    print(ep)

def test_name(name):
    url = args.url.replace("FUZZ", name)
    results = []
    for method in METHODS:
        resp = send(method, url)
        if resp is None:
            results.append(f"{method} (ERR)")
            continue
        results.append(f"{method} ({resp.status_code})")
        if resp.status_code == 401:
            unauthorized.add(f"{method} {url}")
        elif 200 <= resp.status_code < 300:
            authorized.add(f"{method} {url}")

        # confirm the function is real but needs parameters (PGRST202 self-referencing hint)
        try:
            data = resp.json()
        except (requests.exceptions.JSONDecodeError, ValueError):
            continue
        if data.get("code") == "PGRST202":
            fname, params = extract_signature(data.get("hint"))
            if fname == name:
                param_targets[name] = url
                if params:
                    found_params.setdefault(name, set()).update(params)
    print(f"{name}: " + " ".join(results))


print("\n=== Stage 2: testing discovered endpoint names against FUZZ ===")
for ep in sorted(endpoints):
    test_name(ep)
    for v in range(1, 6):
        test_name(f"{ep}_v{v}")

print("\n=== Stage 3: discovering parameters for confirmed endpoints ===")
try:
    with open(PARAM_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        param_words = [line.strip() for line in f if line.strip()]
    print(f"[*] Loaded {len(param_words)} entries from {PARAM_WORDLIST_PATH}\n")
except FileNotFoundError:
    param_words = []
    print(f"Param wordlist not found at '{PARAM_WORDLIST_PATH}', skipping brute force (auto-extracted hints still apply).\n")

for ep, url in param_targets.items():
    for p in sorted(found_params.get(ep, [])):
        print(f"{ep}: {p} [+] (from hint)")

    for param in param_words:
        if param in found_params.get(ep, set()):
            continue
        resp = send("get", f"{url}?{param}=1")
        if resp is None:
            continue
        try:
            data = resp.json()
        except (requests.exceptions.JSONDecodeError, ValueError):
            continue
        # PGRST202 = function/param not found, PGRST100 = unmatched param fell through
        # to result-filter parsing and choked on the raw value (still a wrong guess)
        if data.get("code") not in ("PGRST202", "PGRST100"):
            found_params.setdefault(ep, set()).add(param)
            print(f"{ep}: {param} ({resp.status_code}) [+]")

# single output file with commented sections, ready to reuse as wordlist
with open(OUTPUT_PATH, "w") as f:
    f.write("# Authorized Paths\n")
    f.write("\n".join(sorted(authorized)))
    f.write("\n\n# Unauthorized Paths\n")
    f.write("\n".join(sorted(unauthorized)))
    f.write("\n\n# Function names (from hints)\n")
    f.write("\n".join(sorted(endpoints)))
    f.write("\n\n# Discovered parameters (endpoint: param)\n")
    for ep in sorted(found_params):
        for p in sorted(found_params[ep]):
            f.write(f"{ep}: {p}\n")

print(f"\n[*] Saved to {OUTPUT_PATH}")
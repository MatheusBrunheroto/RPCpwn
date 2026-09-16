import argparse
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProgressBar:
    """Pinned '(current/total)' counter at the bottom of the terminal. Results
    print above it via print_above() without ever clobbering the counter itself.
    Thread-safe: stages fire requests from a pool of worker threads."""

    def __init__(self):
        self.total = 0
        self.current = 0
        self.active = False
        self._lock = threading.Lock()

    def start(self, total):
        with self._lock:
            self.total = total
            self.current = 0
            self.active = True
            self._render()

    def step(self, current=None):
        with self._lock:
            if not self.active:
                return
            self.current = self.current + 1 if current is None else current
            self._render()

    def _render(self):
        sys.stdout.write(f"\r\x1b[2K({self.current}/{self.total})")
        sys.stdout.flush()

    # Clear the counter, print a result line above it, then redraw it below
    def print_above(self, text):
        with self._lock:
            sys.stdout.write("\r\x1b[2K")
            print(text)
            if self.active:
                self._render()

    def finish(self, label):
        with self._lock:
            sys.stdout.write("\r\x1b[2K")
            print(label)
            self.active = False


class RPCpwn:

    METHODS = ["GET", "POST", "PATCH", "PUT", "DELETE"]

    def __init__(self, url, header, wordlist_path, param_wordlist_path):
        self.url = url

        name, value = header.split(":", 1)
        self.headers = {name.strip(): " ".join(value.split())}

        self.words = self._load_wordlist(wordlist_path, required=True)
        print(f"[*] Loaded {len(self.words)} entries from {wordlist_path}\n")
        self.param_words = self._load_wordlist(param_wordlist_path, required=False)

        self.authorized = set()      # status 200 (or any 2xx)
        self.unauthorized = set()    # status 401
        self.endpoints = set()       # function names extracted from hints
        self.seen_results = set()    # unique result signatures already printed
        self.param_targets = {}      # endpoint name -> url, confirmed real but needs params
        self.found_params = {}       # endpoint name -> set of confirmed working param names
        self.status_codes = {}       # "method url" -> status code, for every response seen
        self.progress = ProgressBar()

    def _load_wordlist(self, path, required):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            if required:
                print(f"Wordlist not found at '{path}' (default path, not an argument).")
                raise SystemExit
            print(f"Param wordlist not found at '{path}', skipping brute force (auto-extracted hints still apply).\n")
            return []

    # Grab whatever comes after the last dot in the hint
    def extract_endpoint(self, hint: str):
        if hint and "." in hint:
            return hint.rsplit(".", 1)[-1].strip()
        return None

    # Parse "Perhaps you meant to call the function public.X(p1, p2)" -> ("X", ["p1", "p2"])
    def extract_signature(self, hint: str):
        if not hint or "public." not in hint:
            return None, []
        after = hint.split("public.", 1)[-1].strip()
        if "(" in after and after.endswith(")"):
            fname, params_str = after.split("(", 1)
            params = [p.strip() for p in params_str[:-1].split(",") if p.strip()]
            return fname.strip(), params
        return after.strip(), []

    def send(self, method: str, url: str):
        try:
            return requests.request(method.upper(), url, headers=self.headers, verify=False)
        except requests.exceptions.RequestException as e:
            print(f"[DEBUG] {method} {url} -> {type(e).__name__}: {e}")
            return None

    # Fire all 5 HTTP methods against one URL concurrently, one thread each
    def send_all(self, url):
        with ThreadPoolExecutor(max_workers=len(self.METHODS)) as executor:
            futures = {method: executor.submit(self.send, method, url) for method in self.METHODS}
            return {method: future.result() for method, future in futures.items()}

    # Test a single candidate name against every method, tracking auth state and param hints
    def test_name(self, name):
        url = self.url.replace("FUZZ", name)
        responses = self.send_all(url)
        results = []
        for method in self.METHODS:
            resp = responses[method]
            if resp is None:
                results.append(f"{method} (ERR)")
                continue

            if resp.status_code != 405:
                results.append(f"{method} ({resp.status_code})")
            self.status_codes[f"{method} {url}"] = resp.status_code
            if resp.status_code == 401:
                self.unauthorized.add(f"{method} {url}")
            elif 200 <= resp.status_code < 300:
                self.authorized.add(f"{method} {url}")
                self.param_targets.setdefault(name, url)

            # confirm the function is real but needs parameters (PGRST202 self-referencing hint)
            try:
                data = resp.json()
            except (requests.exceptions.JSONDecodeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            if data.get("code") == "PGRST202":
                fname, params = self.extract_signature(data.get("hint"))
                if fname == name:
                    self.param_targets[name] = url
                    if params:
                        self.found_params.setdefault(name, set()).update(params)

        if results:
            self.progress.print_above(f"{name}: " + " ".join(results))

    # Function discovery: fuzz the wordlist and mine hints for real function names
    def first_stage(self):
        self.progress.start(len(self.words))
        batch_size = 10
        count = 0
        for batch_start in range(0, len(self.words), batch_size):
            batch = self.words[batch_start:batch_start + batch_size]

            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [(word, executor.submit(self.send, "GET", self.url.replace("FUZZ", word))) for word in batch]

            for word, future in futures:
                url = self.url.replace("FUZZ", word)
                resp = future.result()
                got_endpoint = None

                if resp is not None:
                    self.status_codes[f"GET {url}"] = resp.status_code
                    if resp.status_code == 401:
                        self.unauthorized.add(f"GET {url}")
                    elif 200 <= resp.status_code < 300:
                        self.authorized.add(f"GET {url}")

                    try:
                        data = resp.json()
                    except (requests.exceptions.JSONDecodeError, ValueError):
                        data = None
                    if isinstance(data, dict):
                        endpoint = self.extract_endpoint(data.get("hint"))
                        if endpoint:
                            got_endpoint = endpoint
                            self.endpoints.add(endpoint)

                # real-time output: only new, unique discovered endpoint names
                if got_endpoint:
                    line = f"{got_endpoint} [+]"
                    if line not in self.seen_results:
                        self.seen_results.add(line)
                        self.progress.print_above(line)

                count += 1
                self.progress.step(count)
        self.progress.finish("Stage 1 Done")

        print("\n=== Discovered endpoints ===")
        for ep in sorted(self.endpoints):
            print(ep)

    # Endpoint confirmation: re-test discovered names directly, plus _v1.._v5 variants
    def second_stage(self):
        print("\n=== Stage 2: testing discovered endpoint names against FUZZ ===")
        names = []
        for ep in sorted(self.endpoints):
            names.append(ep)
            names.extend(f"{ep}_v{v}" for v in range(1, 6))

        self.progress.start(len(names))
        batch_size = 10
        count = 0
        for batch_start in range(0, len(names), batch_size):
            batch = names[batch_start:batch_start + batch_size]
            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [executor.submit(self.test_name, name) for name in batch]
                for future in futures:
                    future.result()
                    count += 1
                    self.progress.step(count)
        self.progress.finish("Stage 2 Done")

    # Single param guess against one endpoint: GET url?param=1 and classify the result
    def _test_param(self, ep, url, param):
        resp = self.send("get", f"{url}?{param}=1")
        if resp is None:
            return
        try:
            data = resp.json()
        except (requests.exceptions.JSONDecodeError, ValueError):
            return
        # PGRST202 = function/param not found, PGRST100 = unmatched param fell through
        # to result-filter parsing and choked on the raw value (still a wrong guess).
        # A non-object body (bool/number/list) is a plain successful result, not an error.
        code = data.get("code") if isinstance(data, dict) else None
        if code not in ("PGRST202", "PGRST100"):
            self.found_params.setdefault(ep, set()).add(param)
            self.progress.print_above(f"{ep}: {param} ({resp.status_code}) [+]")

    # Parameter discovery: brute-force query-string args against every confirmed endpoint
    def third_stage(self):
        print("\n=== Stage 3: discovering parameters for confirmed endpoints ===")

        pairs = []
        for ep, url in self.param_targets.items():
            for p in sorted(self.found_params.get(ep, [])):
                self.progress.print_above(f"{ep}: {p} [+] (from hint)")

            known = self.found_params.get(ep, set())
            pairs.extend((ep, url, param) for param in self.param_words if param not in known)

        if not pairs:
            print("Nothing to brute force (no confirmed endpoints or empty param wordlist).")
            return

        self.progress.start(len(pairs))
        batch_size = 10
        count = 0
        for batch_start in range(0, len(pairs), batch_size):
            batch = pairs[batch_start:batch_start + batch_size]
            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = [executor.submit(self._test_param, ep, url, param) for ep, url, param in batch]
                for future in futures:
                    future.result()
                    count += 1
                    self.progress.step(count)
        self.progress.finish("Stage 3 Done")

    def save_output(self, output_path):
        with open(output_path, "w") as f:
            f.write("# Authorized Paths\n")
            f.write("\n".join(sorted(self.authorized)))
            f.write("\n\n# Unauthorized Paths\n")
            f.write("\n".join(sorted(self.unauthorized)))
            f.write("\n\n# Function names (from hints)\n")
            f.write("\n".join(sorted(self.endpoints)))
            f.write("\n\n# Discovered parameters (endpoint: param)\n")
            for ep in sorted(self.found_params):
                for p in sorted(self.found_params[ep]):
                    f.write(f"{ep}: {p}\n")
        print(f"\n[*] Saved to {output_path}")


class Report:

    def __init__(self, rpc, path):
        self.rpc = rpc
        self.path = path
        self.text = ""

    def _format_json_body(self, params):
        params = sorted(params)
        lines = []
        for i, p in enumerate(params):
            prefix = "{ " if i == 0 else "  "
            suffix = "," if i < len(params) - 1 else ""
            lines.append(f'{prefix}"{p}": ""{suffix}')
        lines.append(" }")
        return "\n".join(lines)

    # Build the report text: METHOD (status) - URL, plus the accepted JSON body when params exist
    def generate(self):
        blocks = []
        for key in sorted(self.rpc.authorized):
            method, url = key.split(" ", 1)
            status = self.rpc.status_codes.get(key)
            blocks.append(f"{method} ({status}) - {url}")

            name = next((n for n, u in self.rpc.param_targets.items() if u == url), None)
            params = self.rpc.found_params.get(name) if name else None
            if params:
                blocks.append(self._format_json_body(params))
            blocks.append("")
        self.text = "\n".join(blocks).rstrip() + "\n"
        return self.text

    # Print to console and persist to disk
    def write(self):
        print("\n=== Report ===")
        print(self.text)
        with open(self.path, "w") as f:
            f.write(self.text)
        print(f"[*] Report saved to {self.path}")


class CLI:

    def __init__(self):
        self.args = self._parse_args()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.wordlist_path = os.path.join(script_dir, "trigger.txt")
        self.param_wordlist_path = os.path.join(script_dir, "params.txt")

        hostname = urlparse(self.args.url).hostname or "output"
        self.output_path = self._unique_path(f"discovered_endpoints_{hostname}.txt")
        self.report_path = self._unique_path(f"report_{hostname}.txt")

    def _parse_args(self):
        parser = argparse.ArgumentParser(description="Loop over wordlist: test methods, extract function name from hints, save authorized/unauthorized separately")
        parser.add_argument("--url", help="Target URL (use FUZZ where the wordlist entry goes)")
        parser.add_argument("--header", help="Header in 'Name: Value' format")
        return parser.parse_args()

    # Never overwrite: append _1, _2, ... if the file already exists
    def _unique_path(self, path):
        base, ext = os.path.splitext(path)
        suffix = 1
        while os.path.exists(path):
            path = f"{base}_{suffix}{ext}"
            suffix += 1
        return path


if __name__ == "__main__":
    cli = CLI()

    rpc = RPCpwn(cli.args.url, cli.args.header, cli.wordlist_path, cli.param_wordlist_path)
    rpc.first_stage()
    rpc.second_stage()
    rpc.third_stage()
    rpc.save_output(cli.output_path)

    report = Report(rpc, cli.report_path)
    report.generate()
    report.write()

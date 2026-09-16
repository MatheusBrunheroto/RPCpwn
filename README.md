# RPCpwn

CLI tool that enumerates hidden PostgREST/Supabase RPC functions and their parameters purely through error-message analysis — no inputs required beyond a target URL and an API key/header.

> **Disclaimer:** This tool is for educational and authorized security-testing purposes only (CTFs, your own projects, or engagements you are explicitly authorized to test). Do not run it against systems you don't own or don't have written permission to test. The authors take no responsibility for misuse.

## Download

```
git clone https://github.com/MatheusBrunheroto/RPCpwn.git
cd RPCpwn
chmod +x RPCpwn.py
```

## Usage

```
python3 RPCpwn.py --url 'https://<project-ref>.supabase.co/rest/v1/rpc/FUZZ' --header 'Apikey: <anon-key>'
```

- `--url`: target URL with `FUZZ` where the function-name wordlist entry should be substituted.
- `--header`: a single `Name: Value` header (e.g. `Apikey: ...` or `Authorization: Bearer ...`).

## How it works

PostgREST exposes Postgres functions at `POST /rpc/<function_name>` — that's the native convention, true for any PostgREST deployment. On Supabase you'll typically see it one level deeper, at `/rest/v1/rpc/<function_name>`, since their API gateway namespaces every backend service by version (`/rest/v1/`, `/auth/v1/`, `/storage/v1/`, ...); a self-hosted PostgREST instance sitting directly behind its own reverse proxy may not have that extra segment at all. Either way, when you call a function that doesn't exist, or call a real function with the wrong signature, PostgREST replies with a structured error like:

```json
{
  "code": "PGRST202",
  "message": "Could not find the function public.some_function(param) in the schema cache",
  "details": "Searched for the function public.some_function with parameter param, but no matches were found in the schema cache.",
  "hint": "Perhaps you meant to call the function public.some_function(real_param)"
}
```

The `hint` field frequently leaks either the real function name (when you guessed a close typo) or the real parameter name (when the function exists but you called it with the wrong argument). RPCpwn automates guessing across a wordlist and mines every response's `hint` field for these leaks.

## Stages

1. **Function discovery** — loops a wordlist over the target URL (`FUZZ` placeholder), testing GET/POST/PATCH/PUT/DELETE against each candidate. Any response whose `hint` field points to a different function name is recorded as a discovered endpoint. Only new, unique discoveries are printed.
2. **Endpoint confirmation** — re-tests every discovered endpoint name directly (no wordlist noise), plus `_v1` through `_v5` suffixed variants (`get_names`, `get_names_v1`, `get_names_v2`, ...) to catch versioned duplicates of the same function. Prints the status code per method regardless of outcome. Also inspects each response for a self-referencing `PGRST202` hint (the function exists, but was called without the right parameters) and marks it as a parameter-discovery target — auto-capturing the real parameter name for free whenever PostgREST's hint already reveals it.
3. **Parameter discovery** — for every endpoint confirmed in stage 2, brute-forces a second wordlist (`params.txt`) as query-string arguments (`?param=1`). A wrong guess comes back as either `PGRST202` (function/param not found) or `PGRST100` (the unmatched param fell through to PostgREST's result-filter parsing and choked on the raw value); as soon as neither shows up, the parameter name is confirmed and recorded.



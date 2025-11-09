#!/usr/bin/env python3
"""
Plesk Checker (simple login validator)
- Input format per line: <url_or_host[:port][/path]>[:]username[:]password
  or using '|' as separator. Password is allowed to contain ':'.
- If path present (e.g. /login_up.php) will use it; otherwise tries /login_up.php by default.
- Attempts several common field names, checks redirect/cookie/body to decide success.
- Multithreaded, Ctrl+C pause/resume, debug mode, DNS check.
"""
from concurrent.futures import ThreadPoolExecutor
import argparse
import threading
import signal
import sys
import time
import socket
from urllib.parse import urlparse, urljoin
import requests
from colorama import init, Fore
import os
import re
import json

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

pause_event = threading.Event()
pause_event.set()

DEFAULT_PLESK_PORT = 8443  # many Plesk panels use 8443 HTTPS, but we'll not force it if host includes port

# common form field name candidates for Plesk or web login pages
COMMON_FORM_FIELDS = [
    ("login_name", "passwd"),
    ("login", "passwd"),
    ("username", "password"),
    ("login", "password"),
    ("user", "pass"),
    ("login_name", "password")
]

# common failure substrings to look for in response body (lowercase)
FAIL_KEYWORDS = [
    "incorrect", "invalid", "failed", "wrong username", "wrong password", "login is invalid",
    "authentication failed", "invalid login", "access denied"
]

# common success indicators in redirect or cookies
SUCCESS_COOKIE_KEYWORDS = ["PLESKSESSID", "psa_session", "pleskd"]
SUCCESS_LOCATION_KEYWORDS = ["index", "session", "dashboard", "panel", "login_up.php"]


def print_banner():
    banner = r"""
Plesk Checker — Simple Login Validator
"""
    print(Fore.CYAN + banner)


def parse_line(line: str):
    """Parse input line into (raw_url, username, password). Supports '|' or ':' separators.
       Splits from right so password may contain ':'. Returns None if invalid."""
    if not line:
        return None
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    if "|" in s:
        parts = s.split("|")
        if len(parts) >= 3:
            return parts[0].strip(), parts[1].strip(), parts[2].strip()
        return None

    if ":" in s:
        parts = s.rsplit(":", 2)
        if len(parts) == 3:
            return parts[0].strip(), parts[1].strip(), parts[2].strip()
        return None

    return None


def normalize_input_url(raw: str, default_port: int = DEFAULT_PLESK_PORT):
    """
    Normalize the provided raw URL or host:
    - If path present, preserve it (we'll use it as login endpoint).
    - If scheme missing, default to https.
    - If port missing and host looks like domain without explicit port, do not force port,
      but keep default port available if needed.
    Returns (base_url_no_path, path_or_none, full_base_with_port_candidate)
    Where:
      base_url_no_path = scheme://host[:port_if_given]
      path_or_none = path part if present else None
      full_base_with_port_candidate = scheme://host:port  (guaranteed to include a port)
    """
    raw = raw.strip()
    if raw.startswith("//"):
        raw = "https:" + raw

    if not raw.startswith("http://") and not raw.startswith("https://"):
        tmp = "https://" + raw
    else:
        tmp = raw

    parsed = urlparse(tmp)
    scheme = parsed.scheme or "https"
    host = parsed.hostname
    path = parsed.path or ""
    port = parsed.port

    # if parse failed to get host (rare), try splitting by '/'
    if not host:
        head = raw.split("/", 1)[0]
        if ":" in head:
            host_part, port_part = head.split(":", 1)
            host = host_part
            try:
                port = int(port_part)
            except Exception:
                port = None
        else:
            host = head
            port = None
        path = "/" + raw.split("/", 1)[1] if "/" in raw else ""

    base_no_port = f"{scheme}://{host}"
    if port:
        base_no_port = f"{scheme}://{host}:{port}"

    # candidate with explicit port (use default if none)
    final_port = port if port else default_port
    base_with_port = f"{scheme}://{host}:{final_port}"

    # If path is "/" or empty, set None
    if path in (None, "", "/"):
        path = None

    return base_no_port, path, base_with_port


def hostname_resolvable(host_or_base: str) -> bool:
    """Return True if hostname resolves to an IP."""
    try:
        parsed = urlparse(host_or_base)
        host = parsed.hostname or host_or_base
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def try_post_login(session: requests.Session, login_url: str, user: str, pwd: str, timeout: int = 15):
    """Try multiple common form field name combos. Return (success_bool, reason, resp)."""
    for uname_field, pwd_field in COMMON_FORM_FIELDS:
        data = {uname_field: user, pwd_field: pwd}
        try:
            resp = session.post(login_url, data=data, allow_redirects=False, timeout=timeout, verify=False)
        except requests.RequestException as e:
            return False, f"REQUEST_ERROR:{e}", None

        # 1) Redirects indicating success
        loc = resp.headers.get("Location", "") or resp.headers.get("location", "")
        if loc and ("session" in loc.lower() or "index" in loc.lower() or "panel" in loc.lower() or "dashboard" in loc.lower() or "plesk" in loc.lower()):
            return True, f"REDIRECT:{uname_field}/{pwd_field}", resp

        # 2) Cookies indicating session
        scookies = resp.headers.get("Set-Cookie", "") or resp.headers.get("set-cookie", "")
        if scookies:
            low = scookies.lower()
            for kw in SUCCESS_COOKIE_KEYWORDS:
                if kw.lower() in low:
                    return True, f"COOKIE:{uname_field}/{pwd_field}", resp

        # 3) Body checks for failure or success
        body = (resp.text or "").lower()
        # explicit fail keywords
        for fk in FAIL_KEYWORDS:
            if fk in body:
                # this attempt failed but maybe another field name works; continue attempts
                # mark as failure for this attempt
                last_fail_reason = f"BODY_FAIL({fk})"
                break
        else:
            # no fail keywords in body — ambiguous; if status is 200 but we didn't find fail keywords,
            # sometimes login succeeded and returned a page; check for success markers
            if any(k in body for k in ["logout", "session", "logout.php", "my account", "panel"]):
                return True, f"BODY_SUCCESS:{uname_field}/{pwd_field}", resp

        # If 302/303 but no helpful Location, treat specially
        if resp.status_code in (302, 303):
            # some setups redirect but location doesn't include helpful text — still consider success if cookie set
            if scookies:
                return True, f"REDIRECT_NO_LOC_COOKIE:{uname_field}/{pwd_field}", resp

        # otherwise try next field combo
    # after all combos, no success
    return False, "ALL_FIELD_TRIED_FAIL", None


def worker(item, success_file, fail_file, timeout, debug):
    raw_url, user, pwd = item
    base_no_port, path, base_with_port = normalize_input_url(raw_url)
    # prefer to use path if user supplied specific login path
    if path:
        # build login URL from base_no_port + path
        login_endpoint = base_no_port.rstrip("/") + path
        # if path looks like it's the login script (endswith .php) we use it, else append login_up.php
        if not path.lower().endswith(".php") and not path.lower().endswith("/login"):
            login_endpoint = urljoin(base_no_port, "/login_up.php")
    else:
        # default login script
        login_endpoint = urljoin(base_no_port, "/login_up.php")

    # ensure login_endpoint is an absolute URL and has scheme + host + port if needed
    # If input had no explicit port we fall back to base_with_port for DNS/resolution convenience.
    if debug:
        print(Fore.CYAN + f"[DEBUG] raw='{raw_url}' -> base_no_port='{base_no_port}', path='{path}', login_endpoint='{login_endpoint}', port_candidate='{base_with_port}'")

    # DNS check using host from base_no_port
    if not hostname_resolvable(base_no_port):
        # try with candidate port host (base_with_port) too (hostname the same)
        if not hostname_resolvable(base_with_port):
            with threading.Lock():
                print(Fore.YELLOW + f"[SKIP] {base_no_port} | {user} (DNS FAIL)")
                with open(fail_file, "a", encoding="utf-8") as fh:
                    fh.write(f"{base_no_port}|{user}|{pwd} (DNS_FAIL)\n")
            return

    s = requests.Session()
    # try the login endpoint directly; if that yields ambiguous responses, we will try base_with_port/login_up.php as fallback
    ok, reason, resp = try_post_login(s, login_endpoint, user, pwd, timeout=timeout)
    if not ok:
        # fallback: try base_with_port/login_up.php (use candidate with default port)
        fallback_login = base_with_port.rstrip("/") + "/login_up.php"
        if debug:
            print(Fore.CYAN + f"[DEBUG] fallback -> {fallback_login}")
        ok2, reason2, resp2 = try_post_login(s, fallback_login, user, pwd, timeout=timeout)
        if ok2:
            ok, reason, resp = ok2, reason2, resp2
        else:
            ok = False
            reason = reason + "|" + reason2

    with threading.Lock():
        if ok:
            print(Fore.GREEN + f"[SUCCESS] {base_no_port} | {user} -> {reason}")
            with open(success_file, "a", encoding="utf-8") as fh:
                fh.write(f"{base_no_port}|{user}|{pwd}\n")
        else:
            print(Fore.RED + f"[FAILED]  {base_no_port} | {user} -> {reason}")
            with open(fail_file, "a", encoding="utf-8") as fh:
                fh.write(f"{base_no_port}|{user}|{pwd} ({reason})\n")


def handle_ctrl_c(signum, frame):
    pause_event.clear()
    print(Fore.YELLOW + "\nCTRL+C detected. Paused.")
    while True:
        choice = input(Fore.CYAN + "[e]xit or [r]esume? ").strip().lower()
        if choice == "e":
            print(Fore.RED + "Exiting...")
            sys.exit(0)
        if choice == "r":
            pause_event.set()
            print(Fore.GREEN + "Resuming...")
            break
        print(Fore.YELLOW + "Invalid. Enter 'e' or 'r'.")


def choose_sep(s: str):
    if s == "|" or s.lower() == "pipe":
        return "|"
    if s == ":" or s.lower() == "colon":
        return ":"
    return s


def main():
    parser = argparse.ArgumentParser(description="Plesk Checker - simple login validator")
    parser.add_argument("--file", "-f", required=True, help="Input file (one entry per line). Supports '|' or ':' separators.")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Number of worker threads")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds")
    parser.add_argument("--out", "-o", default=None, help="Output file for successes")
    parser.add_argument("--fail", "-F", default=None, help="Output file for fails")
    parser.add_argument("--out-sep", default="|", help="Output separator (default '|')")
    parser.add_argument("--debug", action="store_true", help="Show debug info")
    args = parser.parse_args()

    infile = args.file
    workers = max(1, args.threads)
    timeout = args.timeout
    out_sep = choose_sep(args.out_sep)
    success_file = args.out or f"{os.path.splitext(infile)[0]}_plesk_success.txt"
    fail_file = args.fail or f"{os.path.splitext(infile)[0]}_plesk_failed.txt"
    debug = args.debug

    # prepare output
    open(success_file, "w", encoding="utf-8").close()
    open(fail_file, "w", encoding="utf-8").close()

    try:
        with open(infile, "r", encoding="utf-8") as fh:
            lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"Input file not found: {infile}")
        sys.exit(1)

    entries = []
    for ln in lines:
        parsed = parse_line(ln)
        if not parsed:
            print(Fore.YELLOW + f"[SKIP] Invalid format: {ln}")
            continue
        entries.append(parsed)

    print_banner()
    print(Fore.YELLOW + f"[•] Loaded {len(entries)} entries from {infile}")
    print(Fore.YELLOW + f"[•] Success -> {success_file}")
    print(Fore.YELLOW + f"[•] Failed  -> {fail_file}")
    print(Fore.YELLOW + f"[•] Threads -> {workers}")
    if debug:
        print(Fore.CYAN + "[DEBUG] Debug mode ON\n")

    signal.signal(signal.SIGINT, handle_ctrl_c)

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = []
        for item in entries:
            while not pause_event.is_set():
                time.sleep(0.1)
            futures.append(exe.submit(worker, item, success_file, fail_file, timeout, debug))
        try:
            for f in futures:
                f.result()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()


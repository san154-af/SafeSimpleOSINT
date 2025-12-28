#!/usr/bin/env python3
"""
safe_simple_osint.py

Improved Safe Simple OSINT (educational & legal)

CHANGELOG (FIX):
- ❌ Removed sys.exit(1) from require_permission (caused SystemExit crash)
- ✅ Permission denial now handled gracefully (returns False)
- ✅ main() stops safely without raising SystemExit
- ✅ Works in interactive & non-interactive environments

FEATURES:
1) IP Geolocation
2) IP RDAP
3) Domain RDAP
4) DNS Resolve
5) GitHub User lookup
6) Save last result
7) HTTP headers inspection
8) Reverse DNS lookup
9) Hash lookup (known public hashes only)
10) URL safety check (heuristic)

Usage:
  python safe_simple_osint.py
  python safe_simple_osint.py --yes
  OSINT_ASSUME_PERMISSION=1 python safe_simple_osint.py
"""

import requests
import socket
import sys
import time
import os
import argparse

CONFIRM_PHRASE = "I_HAVE_PERMISSION"

# ---------------- Utilities ----------------

def is_interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def safe_input(prompt: str, default: str | None = None) -> str:
    """Safe input wrapper (no crash in sandbox)."""
    if is_interactive():
        try:
            return input(prompt)
        except OSError:
            return default or ""
    return default or ""


# ---------------- UI ----------------

def banner():
    print("""
==============================
 Safe Simple OSINT Tool
 Educational & Legal Only
==============================
""")


def require_permission(auto_yes: bool = False) -> bool:
    """Ask for legal permission confirmation.

    Returns:
        True  -> permission granted
        False -> permission denied
    """
    if auto_yes or os.getenv("OSINT_ASSUME_PERMISSION") == "1":
        return True

    print("Only use this tool on targets you own or have permission for.")
    print(f"Type exactly: {CONFIRM_PHRASE}")

    ans = safe_input("Confirmation: ", "")
    if ans.strip() != CONFIRM_PHRASE:
        print("[!] Permission denied. Exiting safely.")
        return False

    return True


# ---------------- Helpers ----------------

def pretty(title, value):
    print(f"{title:18}: {value}")


# ---------------- Features ----------------

def ip_geolocation(ip):
    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
    r.raise_for_status()
    return r.json()


def rdap_ip(ip):
    if not ip:
        raise ValueError("IP kosong")
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def rdap_domain(domain):
    if not domain:
        raise ValueError("Domain kosong")
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def github_user(username):
    if not username:
        return None
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SafeSimpleOSINT"
    }
    try:
        r = requests.get(f"https://api.github.com/users/{username}", headers=headers, timeout=8)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        return r.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def dns_resolve(host):
    return socket.gethostbyname_ex(host)


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)
    except Exception:
        return None


def http_headers(url):
    r = requests.head(url, allow_redirects=True, timeout=8)
    return dict(r.headers)


def hash_lookup(h):
    known = {
        "5d41402abc4b2a76b9719d911017c592": "hello"
    }
    return known.get(h.lower())


def url_safety(url):
    red_flags = ["login", "verify", "free", "bonus", "account"]
    score = sum(1 for k in red_flags if k in url.lower())
    return "Suspicious" if score >= 2 else "Looks OK"


# ---------------- CLI ----------------

def menu():
    print("""
1) IP Geolocation
2) IP RDAP
3) Domain RDAP
4) DNS Resolve
5) GitHub User
6) Save Last Result
7) HTTP Headers
8) Reverse DNS
9) Hash Lookup
10) URL Safety Check
0) Exit
""")

last_result = None


def main(argv=None):
    global last_result
    parser = argparse.ArgumentParser()
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)

    banner()

    if not require_permission(args.yes):
        return  # graceful exit, NO SystemExit

    while True:
        menu()
        c = safe_input("Select> ", "0")

        try:
            if c == "1":
                ip = safe_input("IP: ")
                data = ip_geolocation(ip)
                for k, v in data.items(): pretty(k, v)
                last_result = data

            elif c == "2":
                ip = safe_input("IP: ")
                data = rdap_ip(ip)
                if "error" in data:
                    print("RDAP error:", data["error"])
                else:
                    pretty("Handle", data.get("handle"))
                    pretty("Name", data.get("name"))
                    pretty("Type", data.get("type"))
                last_result = data

            elif c == "3":
                d = safe_input("Domain: ")
                data = rdap_domain(d)
                if "error" in data:
                    print("RDAP error:", data["error"])
                else:
                    pretty("Domain", data.get("ldhName"))
                    pretty("Status", data.get("status"))
                last_result = data

            elif c == "4":
                h = safe_input("Host: ")
                last_result = dns_resolve(h)
                print(last_result)

            elif c == "5":
                u = safe_input("GitHub username: ")
                data = github_user(u)
                if not data or "error" in data:
                    print("GitHub lookup gagal:", data.get("error") if data else "unknown")
                else:
                    pretty("Login", data.get("login"))
                    pretty("Repos", data.get("public_repos"))
                    pretty("Followers", data.get("followers"))
                    last_result = data

            elif c == "6":
                if not last_result:
                    print("No data")
                else:
                    fn = safe_input("File: ", "report.txt")
                    with open(fn, "w") as f:
                        f.write(str(last_result))
                    print("Saved")

            elif c == "7":
                url = safe_input("URL: ")
                last_result = http_headers(url)
                print(last_result)

            elif c == "8":
                ip = safe_input("IP: ")
                last_result = reverse_dns(ip)
                print(last_result)

            elif c == "9":
                h = safe_input("Hash: ")
                print("Result:", hash_lookup(h))

            elif c == "10":
                url = safe_input("URL: ")
                print(url_safety(url))

            elif c == "0":
                print("Exit")
                break

            else:
                print("Invalid option")

        except Exception as e:
            print("Error:", e)

        time.sleep(0.2)


# ---------------- Tests ----------------

def _tests():
    # existing tests
    assert hash_lookup("5d41402abc4b2a76b9719d911017c592") == "hello"
    assert url_safety("https://example.com") == "Looks OK"

    # new tests
    assert require_permission(auto_yes=True) is True
    os.environ["OSINT_ASSUME_PERMISSION"] = "1"
    assert require_permission() is True
    os.environ.pop("OSINT_ASSUME_PERMISSION", None)

    print("Tests OK")


if __name__ == "__main__":
    if os.getenv("RUN_TESTS") == "1":
        _tests()
    else:
        main()

#!/usr/bin/env python3
"""Import monthly DB-IP country data through Sibuna's authenticated storage owner."""
import argparse
import datetime
import getpass
import http.client
import ipaddress
import json
import re
import sys
import time
import urllib.parse


class Console:
    def __init__(self, origin):
        url = urllib.parse.urlsplit(origin)
        if (url.scheme not in ("http", "https") or not url.hostname or url.username
                or url.password or url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("Supply a console origin such as http://127.0.0.1:19446")
        if url.scheme == "http":
            try:
                loopback = ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise ValueError("HTTP requires a literal loopback address; otherwise use HTTPS")
        self.url = url
        self.origin = f"{url.scheme}://{url.netloc}"
        self.cookie = None
        self.csrf = None

    def request(self, method, endpoint, body=None):
        connection = (http.client.HTTPSConnection if self.url.scheme == "https"
                      else http.client.HTTPConnection)(
                          self.url.hostname, self.url.port, timeout=20)
        headers = {"Origin": self.origin}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf:
            headers["X-Console-CSRF"] = self.csrf
        try:
            connection.request(method, "/console/api/" + endpoint,
                               json.dumps(body) if body is not None else None, headers)
            response = connection.getresponse()
            data = response.read(65537)
            if len(data) > 65536:
                raise RuntimeError("Console response exceeds 64 KiB")
            if response.status != 200:
                raise RuntimeError(f"{endpoint}: HTTP {response.status}; check access and state")
            if endpoint == "login":
                self.cookie = response.getheader("Set-Cookie", "").split(";", 1)[0]
            return json.loads(data)
        finally:
            connection.close()


def import_country(console, month, checksum, timeout):
    before = console.request("GET", "geoip")
    if before["source_version"] == month and before["ranges"] > 0:
        if checksum and before["digest"].lower() != checksum.lower():
            raise RuntimeError("Active month has a different checksum; inspect GeoIP status")
        print("Requested month is already active; no import needed")
        print(json.dumps(before, indent=2))
        return
    console.request("POST", "geoip", {
        "source_version": month, "expected_revision": before["revision"],
        "checksum": checksum,
    })
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        metadata = console.request("GET", "geoip")
        progress = (metadata["status"], metadata["processed_ranges"])
        if progress != last:
            print(f"{progress[0]}: {progress[1]:,} ranges", flush=True)
            last = progress
        if metadata["status"] == "applied":
            if (metadata["revision"] != before["revision"] + 1
                    or metadata["source_version"] != month):
                raise RuntimeError("Another import changed the generation; inspect GeoIP status")
            print(json.dumps(metadata, indent=2))
            return
        if metadata["status"] == "failed":
            raise RuntimeError("Import failed; previous generation retained. Inspect daemon logs")
        time.sleep(2)
    raise RuntimeError("Polling deadline reached; import may still be running. Check GeoIP status")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="Console origin, without /console/")
    parser.add_argument("--username", required=True)
    parser.add_argument("--month", default=datetime.date.today().strftime("%Y-%m"))
    parser.add_argument("--checksum", default="", help="Optional expected .csv.gz SHA-256")
    parser.add_argument("--totp", action="store_true", help="Prompt for TOTP or recovery code")
    parser.add_argument("--status", action="store_true", help="Read active generation only")
    parser.add_argument("--timeout", type=int, default=1200, help="Polling deadline in seconds")
    args = parser.parse_args()
    if not re.fullmatch(r"20\d{2}-(0[1-9]|1[0-2])", args.month):
        parser.error("month must be YYYY-MM (2000–2099)")
    if args.checksum and not re.fullmatch(r"[0-9a-fA-F]{64}", args.checksum):
        parser.error("checksum must contain 64 hexadecimal characters")
    if not 1 <= args.timeout <= 86400:
        parser.error("timeout must be between 1 and 86400 seconds")
    console = Console(args.origin)
    try:
        session = console.request("POST", "login", {
            "username": args.username, "password": getpass.getpass("Password: "),
            "code": getpass.getpass("TOTP or recovery code: ") if args.totp else "",
        })
        console.csrf = session["csrf"]
        if session["must_change"] or session["totp_required"]:
            raise RuntimeError("Complete password change or TOTP setup in the console first")
        if args.status:
            print(json.dumps(console.request("GET", "geoip"), indent=2))
        else:
            import_country(console, args.month, args.checksum, args.timeout)
    finally:
        if console.cookie:
            try:
                console.request("POST", "logout", {})
            except (OSError, RuntimeError, ValueError, http.client.HTTPException):
                print("Could not sign out CLI session; revoke it in the console", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, http.client.HTTPException) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit("Interrupted; a submitted import may still be running")

#!/usr/bin/env python3
# pylint: disable=line-too-long, broad-exception-caught
""" Detect CMS/frameworks using lightweight HTTP heuristics."""

import argparse
import base64
import binascii
import json
import os
import re
import sys
import urllib.parse

import requests
import urllib3

# ANSI colors (preserved from your original)
PURPLE = '\033[95m'
CYAN = '\033[96m'
DARKCYAN = '\033[36m'
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
END = '\033[0m'


class FingerprintMatcher:
    """
    Prepares and evaluates fingerprints efficiently.
    Compiles regexes and normalizes values for faster matching.
    """
    def __init__(self, fingerprints):
        # Pre-compile regex patterns and keep structure as-is for other types
        self.cms_list = []
        for cms in fingerprints:
            prepared = []
            for fp in cms.get("fingerprints", []):
                fptype = fp.get("type")
                if fptype == "regex":
                    pattern = fp.get("value", "")
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                    except re.error:
                        continue
                    prepared.append({"type": "regex", "compiled": compiled, "raw": pattern})
                else:
                    prepared.append(fp)
            self.cms_list.append({"name": cms.get("name", "Unknown"), "fingerprints": prepared})

    def match(self, response: requests.Response, response_text_lower: str):
        """
        Returns list of dicts: {"name": <cms>, "matched_by": [<description>...]}
        """
        results = []

        headers = response.headers
        cookies = response.cookies

        for cms in self.cms_list:
            matched_by = []
            for frpr in cms["fingerprints"]:
                t = frpr.get("type")

                # Body regex
                if t == "regex":
                    if frpr["compiled"].search(response_text_lower):
                        matched_by.append(f"regex:{frpr['raw']}")

                # Body contains
                elif t == "string_contains":
                    value = str(frpr.get("value", "")).lower()
                    if value and value in response_text_lower:
                        matched_by.append(f"string_contains:{frpr['value']}")

                elif t == "strings_contain":
                    required_values = str(frpr.get("value", "")).lower().split("|")
                    if required_values and all(v in response_text_lower for v in required_values):
                        matched_by.append(f"strings_contain:{frpr['value']}")

                # Header checks
                elif t == "header_key_equals":
                    key = frpr.get("value", "")
                    if key and key in headers:
                        matched_by.append(f"header_key_equals:{key}")

                elif t == "header_key_value":
                    key = frpr.get("key", "")
                    value = str(frpr.get("value", "")).lower()
                    if key in headers and str(headers.get(key, "")).lower() == value:
                        matched_by.append(f"header_key_value:{key}={frpr['value']}")

                elif t == "header_key_value_contains":
                    key = frpr.get("key", "")
                    value = str(frpr.get("value", "")).lower()
                    if key in headers and value in str(headers.get(key, "")).lower():
                        matched_by.append(f"header_key_value_contains:{key}~{frpr['value']}")

                # Cookie checks
                elif t == "cookie_key_equals":
                    key = frpr.get("value", "")
                    if key and key in cookies:
                        matched_by.append(f"cookie_key_equals:{key}")

                elif t == "cookie_key_value":
                    key = frpr.get("key", "")
                    value = str(frpr.get("value", "")).lower()
                    if key in cookies and str(cookies.get(key, "")).lower() == value:
                        matched_by.append(f"cookie_key_value:{key}={frpr['value']}")

                elif t == "cookie_key_value_contains":
                    key = frpr.get("key", "")
                    value = str(frpr.get("value", "")).lower()
                    if key in cookies and value in str(cookies.get(key, "")).lower():
                        matched_by.append(f"cookie_key_value_contains:{key}~{frpr['value']}")

                elif t == "cookie_key_value_b64_json_keys":
                    key = frpr.get("key", "")
                    required_keys = str(frpr.get("value", "")).lower().split("|")
                    if key in cookies:
                        try:
                            url_decoded = urllib.parse.unquote(cookies.get(key, ""))
                            b64_decoded = base64.b64decode(url_decoded)
                            json_decoded = json.loads(b64_decoded)

                            json_keys_lower = {str(k).lower() for k in json_decoded.keys()}
                            if all(k in json_keys_lower for k in required_keys):
                                matched_by.append(f"cookie_key_value_b64_json_keys:{key} has {frpr['value']}")
                        except (binascii.Error, json.decoder.JSONDecodeError, ValueError, TypeError):
                            pass

                elif t == "cookie_substr_key_value_b64_type":
                    end_len = int(frpr.get("length", 0))
                    key_suffix = frpr.get("key", "")
                    expected_type_name = frpr.get("value", "")
                    try:
                        for cookie in cookies:
                            if cookie.name[end_len:] == key_suffix:
                                try:
                                    url_decoded = urllib.parse.unquote(cookie.value)
                                    b64_decoded = base64.b64decode(url_decoded)
                                    if type(b64_decoded).__name__ == expected_type_name:
                                        matched_by.append(
                                            f"cookie_substr_key_value_b64_type:*{key_suffix} -> {expected_type_name}"
                                        )
                                        break
                                except binascii.Error:
                                    continue
                    except Exception:
                        pass

            if matched_by:
                results.append({"name": cms["name"], "matched_by": matched_by})

        return results


class CMSDetector:
    """ CMS Detector """

    def __init__(self, host: str, *, raw: bool = False, json_out: bool = False, insecure: bool = False, timeout: int = 10, user_agent: str | None = None):
        self.session = requests.Session()
        self.host = self._normalize_host(host)
        self.raw = raw
        self.json_out = json_out
        self.insecure = insecure
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"

        self._headers = {
            "User-Agent": self.user_agent,
            "Cache-Control": "max-age=0",
            "sec-ch-ua": "\"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\", \"Not;A=Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"macOS\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "upgrade-insecure-requests": "1",
            "referer": self.host
        }

        self.fingerprints = self._load_fingerprints()
        self.matcher = FingerprintMatcher(self.fingerprints)


    @staticmethod
    def _normalize_host(host: str) -> str:
        host = (host or "").strip()
        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        # remove trailing slash
        return host.rstrip("/")


    @staticmethod
    def _load_fingerprints():
        fp_path = os.path.join(".", "fingerprints.json")
        if os.path.exists(fp_path):
            with open(fp_path, "r", encoding="utf-8") as f:
                return json.load(f)
        print(f'{RED}[!] Could not find "fingerprints.json".{END}')
        sys.exit(1)


    def scan(self):
        """ Scan host for CMS """
        if not (self.raw or self.json_out):
            print(PURPLE + BOLD + "CMS Detector" + END)
            print(PURPLE + "[•] Made by: https://github.com/joshuavanderpoll/CMS-Detector" + END)
            print(f"{BLUE}[@] Scanning host {DARKCYAN}\"{self.host}\"{BLUE}...{END}")

        try:
            resp = self.session.get(
                self.host,
                headers=self._headers,
                allow_redirects=True,
                timeout=self.timeout,
                verify=not self.insecure,
            )
        except requests.exceptions.RequestException as e:
            msg = f"{RED}[!] Could not retrieve host. Error: {e}{END}"
            if self.json_out:
                print(json.dumps({"host": self.host, "error": str(e)}, ensure_ascii=False))
            else:
                print(msg)
            sys.exit(1)

        body_lower = resp.text.lower().replace("'", "\"").strip()
        matches = self.matcher.match(resp, body_lower)
        detected = bool(matches)

        if self.json_out:
            out = {
                "host": self.host,
                "status_code": resp.status_code,
                "detected": detected,
                "matches": matches,
                "timing_ms": int(resp.elapsed.total_seconds() * 1000) if resp.elapsed else None,
                "redirects": len(resp.history),
            }
            print(json.dumps(out, ensure_ascii=False))
        elif self.raw:
            if detected:
                # print all matched
                for m in matches:
                    print(GREEN + m["name"].lower().replace(" ", "_") + END)
            else:
                print("null")
        else:
            if detected:
                names = ", ".join(f"\"{m['name']}\"" for m in matches)
                print(f"{GREEN}[√] \"{self.host}\" is using {BLUE}{names}{GREEN}!{END}")
                for m in matches:
                    # Show a concise reason for each CMS
                    reasons = "; ".join(m["matched_by"][:3])
                    if len(m["matched_by"]) > 3:
                        reasons += f" (+{len(m['matched_by'])-3} more)"
                    print(f"{CYAN}    ↳ matched by: {reasons}{END}")
            else:
                print(f"{YELLOW}[!] No CMS could be detected.{END}")

        # Exit codes: 0=found, 2=no match
        sys.exit(0 if detected else 2)


def main():
    """ CLI entry point """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(
        prog="CMS Detector",
        description="Detect common CMS/frameworks using lightweight HTTP heuristics.",
        epilog="Created by: https://github.com/joshuavanderpoll"
    )
    parser.add_argument('--host', type=str, help="Host or URL to scan (e.g., example.com or https://example.com)")
    parser.add_argument('--raw', default=False, action='store_true', help="Print only result name(s) in lowercase with underscores; print 'null' on no match.")
    parser.add_argument('--json', dest='json_out', default=False, action='store_true', help="Output a structured JSON result.")
    parser.add_argument('--timeout', type=int, default=10, help="HTTP timeout in seconds (default: 10).")
    parser.add_argument('--insecure', default=False, action='store_true', help="Skip TLS verification (verify=False).")
    parser.add_argument('--ua', dest='user_agent', type=str, default=None, help="Custom User-Agent string.")

    args = parser.parse_args()

    # Interactive prompt fallback (preserved)
    host = args.host
    if host is None and not args.json_out and not args.raw:
        host = input(PURPLE + "[?] Enter host to scan : " + END)

    elif host is None:
        # If --json or --raw and no host provided, fail cleanly
        print(json.dumps({"error": "Missing --host"}, ensure_ascii=False) if args.json_out
              else f"{RED}[!] Missing --host{END}")
        sys.exit(1)

    detector = CMSDetector(
        host=host,
        raw=args.raw,
        json_out=args.json_out,
        insecure=args.insecure,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    detector.scan()


if __name__ == "__main__":
    main()

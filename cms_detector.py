import requests
import argparse
import json
import base64
import urllib.parse
import urllib3
import re
import os
import binascii
import readline


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


class CMSDetector:
    def __init__(self, host, raw=False) -> None:
        self.session = requests.session()
        self.host = host
        self.fingerprints = []
        self.raw = raw

        self.load_fingerprints()
        self.scan_cms()


    def load_fingerprints(self):
        if os.path.exists("./fingerprints.json"):
            with open("./fingerprints.json", "r") as f:
                self.fingerprints = json.loads(f.read())
        else:
            print(f"{RED}[!] Could not find \"fingerprints.json\".")
            exit(1)


    def scan_cms(self):
        if not self.raw:
            print(f"{BLUE}[@] Scanning host {DARKCYAN}\"{self.host}\"{BLUE}...")

        try:
            response = self.session.get(self.host, headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
                "Cache-Control": "max-age=0",
                "sec-ch-ua": "\"Chromium\";v=\"106\", \"Google Chrome\";v=\"106\", \"Not;A=Brand\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"macOS\"",
                "sec-fetch-dest": "iframe",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-site",
                "upgrade-insecure-requests": "1",
                "referer": self.host
            }, verify=False)
        except Exception as e:
            print(f"{RED}[!] Could not retrieve host. Error: ", e)
            exit(1)

        self.match_response(response)


    def match_response(self, response: requests.Response):
        response_text = response.text.lower().replace("'", "\"").strip()

        for cms in self.fingerprints:
            match = False
            for frpr in cms['fingerprints']:

                # Regex match
                if frpr['type'] == 'regex':
                    if re.search(frpr['value'], response_text, re.IGNORECASE):
                        match = True
                        break

                # Check if body contains string
                if frpr['type'] == 'string_contains':
                    if str(frpr['value']).lower() in response_text:
                        match = True
                        break

                # Check if body contains string
                if frpr['type'] == 'strings_contain':
                    required_values = str(frpr['value']).lower().split("|")

                    if all(substring in response_text for substring in required_values):
                        match = True
                        break

                # Check if header key exists
                if frpr['type'] == 'header_key_equals':
                    if frpr['value'] in response.headers:
                        match = True
                        break

                # Check if header key/value exists
                if frpr['type'] == 'header_key_value':
                    if frpr['key'] in response.headers and str(response.headers[frpr['key']]).lower() == str(frpr['value']).lower():
                        match = True
                        break

                # Check if header key contains string in value
                if frpr['type'] == 'header_key_value_contains':
                    if frpr['key'] in response.headers and str(frpr['value']).lower() in str(response.headers[frpr['key']]).lower():
                        match = True
                        break

                # Check if cookie key exists
                if frpr['type'] == 'cookie_key_equals':
                    if frpr['value'] in response.cookies:
                        match = True
                        break

                # Check if cookie key/value exists
                if frpr['type'] == 'cookie_key_value':
                    if frpr['key'] in response.cookies and str(response.cookies[frpr['key']]).lower() == str(frpr['value']).lower():
                        match = True
                        break

                # Check if cookie key contains string in value
                if frpr['type'] == 'cookie_key_value_contains':
                    if frpr['key'] in response.cookies and str(frpr['value']).lower() in str(response.cookies[frpr['key']]).lower():
                        match = True
                        break

                # # Check if cookie key/value its keys after decoding
                if frpr['type'] == 'cookie_key_value_b64_json_keys':
                    required_keys = str(frpr['value']).lower().split("|")

                    if frpr['key'] in response.cookies:
                        try:
                            url_decoded = urllib.parse.unquote(response.cookies[frpr['key']])
                            b64_decoded = base64.b64decode(url_decoded)
                            json_decoded = json.loads(b64_decoded)

                            if all(key in json_decoded for key in required_keys):
                                match = True
                                break
                        except (binascii.Error, json.decoder.JSONDecodeError):
                            pass

                # Checks end of header key and value type after decoding from Base64
                if frpr['type'] == 'cookie_substr_key_value_b64_type':
                    for cookie in response.cookies:
                        if cookie.name[frpr['length']:] == frpr['key']:
                            try:
                                url_decoded = urllib.parse.unquote(cookie.value)
                                b64_decoded = base64.b64decode(url_decoded)

                                if type(b64_decoded).__name__ == frpr['value']:
                                    match = True
                                    break
                            except (binascii.Error):
                                pass

            if match:
                if not self.raw:
                    print(f"{GREEN}[√] \"{self.host}\" is using {BLUE}\"{cms['name']}\"{GREEN}!")
                else:
                    print(GREEN + str(cms['name']).lower().replace(" ", "_"))
                return

        if not self.raw:
            print("[!] No CMS could be detected.")
        else:
            print('null')
            

if __name__ == "__main__":
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Arguments
    parser = argparse.ArgumentParser(prog = 'CMS Detector', description = 'What the program does', epilog = 'Created by: https://github.com/joshuavanderpoll')
    parser.add_argument('--host', default=None, type=str)
    parser.add_argument('--raw', default=False, action='store_true', help="Returns only the result (null = No result)")
    args = parser.parse_args()

    # Credits
    if not args.raw:
        print(PURPLE + BOLD + "CMS Detector script")
        print(END + PURPLE + "[•] Made by: https://github.com/joshuavanderpoll/CMS-Detector" + RED)

    if args.host == None:
        args.host = input(PURPLE + "[?] Enter host to scan : " + END)

    if args.host[0:7] != "http://" and args.host[0:8] != "https://":
        args.host = f"http://{args.host}"

    args.host = args.host.rstrip("/").strip()

    CMSDetector(args.host, args.raw)
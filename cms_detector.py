import requests
import argparse
import json
import base64
import urllib.parse
import urllib3
import re
import readline


class CMSDetector:
    def __init__(self, host) -> None:
        self.session = requests.session()
        self.host = host

        self.scan_cms()

    def scan_cms(self):
        print(f"[@] Scanning host {self.host}...")

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
        }, verify=False, allow_redirects=True)

        if self.is_laravel(response):
            return print("[√] CMS is using Laravel!")
        elif self.is_wordpress(response):
            return print("[√] CMS is using WordPress!")
        elif self.is_drupal(response):
            return print("[√] CMS is using Drupal!")
        elif self.is_shopify(response):
            return print("[√] CMS is using Shopify!")
        elif self.is_litespeed(response):
            return print("[√] CMS is using LiteSpeed!")
        elif self.is_prestashop(response):
            return print("[√] CMS is using PrestaShop!")
        elif self.is_squarespace(response):
            return print("[√] CMS is using SquareSpace!")
        elif self.is_sanity(response):
            return print("[√] CMS is using Sanity!")
        elif self.is_wix(response):
            return print("[√] CMS is using Wix!")
        elif self.is_microsoft_asp(response):
            return print("[√] CMS is using Microsoft ASP!")
        elif self.is_nextjs(response):
            return print("[√] CMS is using Next.js!")
        elif self.is_jouwweb(response):
            return print("[√] CMS is using JouwWeb!")

        print("[!] No CMS could be detected.")


    def is_laravel(self, response: requests.Response) -> bool:
        try:
            xsrf_token = False
            session_cookie = False

            for cookie in response.cookies:
                if cookie.name == "XSRF-TOKEN":
                    xsrf_value = json.loads(base64.b64decode(urllib.parse.unquote(cookie.value)))
                    if "iv" in xsrf_value and "value" in xsrf_value and "mac" in xsrf_value:
                        xsrf_token = True
                if cookie.name[-8:] == "_session":
                    session_value = base64.b64decode(urllib.parse.unquote(cookie.value))
                    if type(session_value) == bytes:
                        session_cookie = True

            return (session_cookie and xsrf_token)
        except:
            return False


    def is_wordpress(self, response: requests.Response) -> bool:
        if re.search(r'<meta name="generator" content="WordPress (.+?)" \/>', response.text, re.IGNORECASE):
            return True
        if "/wp-content/" in response.text.lower() or "/wp-json/" in response.text.lower() or "/wp-includes/" in response.text.lower():
            return True


    def is_shopify(self, response: requests.Response) -> bool:
        if "X-Shopify-Stage" in response.headers:
            return True
        if "Link" in response.headers and "https://cdn.shopify.com" in response.headers["Link"]:
            return True
        if re.search(r'<link rel="preconnect" href="https:\/\/cdn\.shopify\.com".*>', response.text, re.IGNORECASE):
            return True
        if "<style data-shopify>" in response.text.lower():
            return True


    def is_drupal(self, response: requests.Response) -> bool:
        if "X-Generator" in response.headers and "drupal" in response.headers["X-Generator"].lower():
            return True
        if "X-Drupal-Cache" in response.headers:
            return True
        if re.search(r'<meta name="Generator" content="Drupal (.+?) .*" \/>', response.text, re.IGNORECASE):
            return True
        if re.search(r'<script src="\/core\/misc\/drupal\.js\?v=(.+?)"><\/script>', response.text, re.IGNORECASE):
            return True
        if re.search(r'<script src="\/core\/misc\/drupal\.init\.js\?v=(.+?)"><\/script>', response.text, re.IGNORECASE):
            return True
        if "data-drupal-selector" in response.text.lower() or "data-drupal-form-fields" in response.text.lower() or "data-drupal-link-system-path" in response.text.lower():
            return True


    def is_litespeed(self, response: requests.Response) -> bool:
        if "Server" in response.headers and "litespeed" in response.headers["Server"].lower():
            return True


    def is_prestashop(self, response: requests.Response) -> bool:
        if "Powered-By" in response.headers and "prestashop" in response.headers["Powered-By"].lower():
            return True
        if "/modules/prestatemplate/" in response.text:
            return True
        if "var prestashop = {" in response.text:
            return True
        if "<a href=\"https://www.prestashop.com\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">" in response.text:
            return True


    def is_squarespace(self, response: requests.Response) -> bool:
        if "Server" in response.headers and "squarespace" in response.headers["Server"].lower():
            return True
        if "<link rel=\"preconnect\" href=\"https://images.squarespace-cdn.com\">" in response.text.lower():
            return True
        if "<!-- this is squarespace. -->" in response.text.lower() or "<!-- end of squarespace headers -->" in response.text.lower():
            return True


    def is_sanity(self, response: requests.Response) -> bool:
        if re.search(r'<link rel="preconnect" crossorigin href="https:\/\/cdn\.sanity\.io"\/>', response.text, re.IGNORECASE):
            return True


    def is_wix(self, response: requests.Response) -> bool:
        if "X-Wix-Request-ID" in response.headers:
            return True
        if "Server" in response.headers and "pepyaka" in response.headers["Server"].lower():
            return True


    def is_microsoft_asp(self, response: requests.Response) -> bool:
        if "X-Powered-By" in response.headers and "asp.net" in response.headers["X-Powered-By"].lower():
            return True


    def is_nextjs(self, response: requests.Response) -> bool:
        if "X-Powered-By" in response.headers and "next.js" in response.headers["X-Powered-By"].lower():
            return True


    def is_jouwweb(self, response: requests.Response) -> bool:
        if 'powered by <a href="https://www.jouwweb.nl" rel="">jouwweb</a>' in response.text.lower().strip():
            return True
        if 'window.jouwweb = window.jouwweb' in response.text.lower() or "jouwweb.templateConfig = {" in response.text.lower():
            return True
            

if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(prog = 'CMS Detector', description = 'What the program does', epilog = 'Created by: https://github.com/joshuavanderpoll')
    parser.add_argument('--host', default=None, type=str)
    args = parser.parse_args()

    if args.host == None:
        args.host = input("[?] Enter host to scan : ")

    if args.host[0:7] != "http://" and args.host[0:8] != "https://":
        args.host = f"http://{args.host}"

    args.host = args.host.rstrip("/").strip()

    CMSDetector(args.host)
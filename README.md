# CMS-Detector
A lightweight Python script to detect which **CMS or framework** a given website is running, based on HTTP response fingerprints.

## ✨ Features
- Detects 30+ CMS/frameworks (WordPress, Drupal, Shopify, Laravel, Wix, …).
- Multiple fingerprint methods:
    - HTML body regex & string search
    - HTTP headers
    - Cookies (including Base64/JSON decoding)
- CLI modes:
    - Standard (colorful output)
    - Raw (--raw) → just the CMS name (script-friendly)
    - JSON (--json) → structured output
- Works with both http:// and https:// targets.

## 📦 Installation
```bash
# Clone the repository
git clone https://github.com/joshuavanderpoll/CMS-Detector.git
cd CMS-Detector

# Create & activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Linux/Mac or '. .venv/bin/activate'
.venv\Scripts\activate      # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Scan
```bash
python3 cms_detector.py --host "https://wordpress.com"
```

Output:
```
CMS Detector
[•] Made by: https://github.com/joshuavanderpoll/CMS-Detector
[@] Scanning host "https://wordpress.com"...
[√] "https://wordpress.com" is using "WordPress"!
    ↳ matched by: string_contains:/wp-content/
```

### Raw Mode (Script friendly)
```bash
python3 cms_detector.py --host "https://wordpress.com" --raw
```

Output:
```
wordpress
```

###JSON output
```bash
python3 cms_detector.py --host "https://wordpress.com" --json
```

Output:
```json
{"host": "https://wordpress.com", "status_code": 200, "detected": true, "matches": [{"name": "WordPress", "matched_by": ["string_contains:/wp-content/"]}], "timing_ms": 192, "redirects": 0}
```

## ⚡ Options
| Option       | Description                                             |
| ------------ | ------------------------------------------------------- |
| `--host`     | Target host (e.g. `example.com`, `https://example.com`) |
| `--raw`      | Print only CMS name(s) in lowercase (e.g. `wordpress`)  |
| `--json`     | Return structured JSON output                           |
| `--timeout`  | Set request timeout (default: 10s)                      |
| `--insecure` | Disable SSL verification (`verify=False`)               |
| `--ua`       | Custom User-Agent string                                |

## ✅ Supported CMS / Frameworks
- [x] <a href="https://laravel.com/" target="_blank">Laravel</a>
- [x] <a href="https://wordpress.com/" target="_blank">WordPress</a>
- [x] <a href="https://www.drupal.org/" target="_blank">Drupal</a>
- [x] <a href="https://www.lightspeedhq.nl/" target="_blank">Lightspeed</a>
- [x] <a href="https://www.shopify.com/" target="_blank">Shopify</a>
- [x] <a href="https://www.prestashop.com/" target="_blank">PrestaShop</a>
- [x] <a href="https://www.squarespace.com/" target="_blank">Squarespace</a>
- [x] <a href="https://www.sanity.io/" target="_blank">Sanity</a>
- [x] <a href="https://wix.com/" target="_blank">Wix</a>
- [x] <a href="https://nextjs.org/" target="_blank">Next.js</a>
- [x] <a href="https://dotnet.microsoft.com/en-us/apps/aspnet" target="_blank">Microsoft ASP</a>
- [x] <a href="https://jouwweb.nl/" target="_blank">JouwWeb</a>
- [x] <a href="https://magento.com/" target="_blank">Magento</a>
- [x] <a href="https://www.weebly.com/" target="_blank">Weebly</a>
- [x] <a href="https://www.joomla.org/" target="_blank">Joomla</a>
- [x] <a href="https://www.blogger.com/" target="_blank">Blogger</a>
- [x] <a href="https://www.silverstripe.org/" target="_blank">SilverStripe CMS</a>
- [x] Icordis CMS
- [x] <a href="https://sulu.io/" target="_blank">Sulu CMS</a>
- [x] <a href="https://www.gatsbyjs.com/" target="_blank">Gatsby</a>
- [x] <a href="https://webflow.com/" target="_blank">Webflow</a>
- [x] <a href="https://www.zendesk.nl/" target="_blank">Zendesk</a>
- [x] <a href="https://www.djangoproject.com/" target="_blank">Django</a>
- [x] <a href="https://www.coremedia.com/" target="_blank">CoreMedia CMS</a>
- [x] <a href="https://processwire.com/" target="_blank">ProcessWire CMS</a>
- [x] <a href="https://typo3.org/" target="_blank">TYPO3</a>
- [x] <a href="https://bloxcms.com/" target="_blank">Blox CMS</a>
- [x] <a href="https://www.odoo.com/" target="_blank">Odoo</a>
- [x] <a href="https://www.netlify.com/" target="_blank">Netifly</a>

## 📅 Upcoming
- [ ] <a href="https://www.duda.co/" target="_blank">Duda</a>
- [ ] <a href="https://www.godaddy.com/" target="_blank">GoDaddy</a>
- [ ] <a href="https://www.adobe.com/products/dreamweaver.html" target="_blank">Adobe Dreamweaver</a>
- [ ] <a href="https://strato.nl/" target="_blank">Strato Website</a>
- [ ] <a href="https://sites.google.com/" target="_blank">Google Sites</a>
- [ ] <a href="https://www.salesforce.com/" target="_blank">Salesforce</a>

## 🔍 Fingerprint Types
- `regex` → Match regex in HTML
- `string_contains` → HTML contains substring
- `strings_contain` → HTML contains all substrings (pipe-separated)
- `header_key_equals` → Header key exists
- `header_key_value` → Header key/value match
- `header_key_value_contains` → Header key’s value contains substring
- `cookie_key_equals` → Cookie key exists
- `cookie_key_value` → Cookie key/value match
- `cookie_key_value_contains` → Cookie value contains substring
- `cookie_key_value_b64_json_keys` → Decode cookie from Base64 → JSON → check for keys
- `cookie_substr_key_value_b64_type` → Check cookie name suffix, decode Base64, verify value type
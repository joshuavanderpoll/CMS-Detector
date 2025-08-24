# CMS-Detector
A lightweight fast Go script to detect which **CMS or framework** a given website is running, based on HTTP response fingerprints.

## ✨ Features
- Detects 60+ CMS/frameworks (WordPress, Drupal, Shopify, Laravel, Wix, …).
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
> Prereq: Go 1.24+ (for go install). For prebuilt binaries from Releases, no Go toolchain is required.

### 1) Install from GitHub Releases (recommended)
Download a prebuilt binary for your OS/arch from the Releases page and put it on your PATH.
- **Releases**: https://github.com/joshuavanderpoll/CMS-Detector/releases
- **Artifacts naming**: cmsdetector_<VERSION>_<GOOS>_<GOARCH>.(tar.gz|zip)<br>
  Examples:
  - cmsdetector_v1.0.0_linux_amd64.tar.gz
  - cmsdetector_v1.0.0_darwin_arm64.tar.gz
  - cmsdetector_V1.0.0_windows_amd64.zip

#### Linux/macOS:
```bash
# pick the right asset from the release page
tar -xzf cmsdetector_v1.0.0_linux_amd64.tar.gz
chmod +x cmsdetector_v1.0.0_linux_amd64/cmsdetector
sudo mv cmsdetector_v1.0.0_linux_amd64/cmsdetector /usr/local/bin/cms_detector
cms_detector --help
```

#### Windows
```powershell
Expand-Archive .\cmsdetector_V1.0.0_windows_amd64.zip -DestinationPath .
Move-Item .\cmsdetector_V1.0.0_windows_amd64\cmsdetector.exe $Env:ProgramFiles\cms_detector\cms_detector.exe
$Env:ProgramFiles\cms_detector\cms_detector.exe --help
```

### 2) Install via go install (from the repo)
This builds and installs directly from the repo’s module path.
```bash
go install github.com/joshuavanderpoll/CMS-Detector@latest
# or use a specific version:
go install github.com/joshuavanderpoll/CMS-Detector@v1.0.0

# Usage
~/go/bin/CMS-Detector --help
```

### 3) Build from source (clone & build)
```bash
# Clone the repository
git clone https://github.com/joshuavanderpoll/CMS-Detector.git
cd CMS-Detector

# Build the Go binary
go build -o cms_detector ./cms_detector.go
```

## 🚀 Usage

### Basic Scan
```bash
./cms_detector --host "https://wordpress.com"
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
./cms_detector --host "https://wordpress.com" --raw
```

Output:
```
wordpress
```

### JSON output
```bash
./cms_detector --host "https://wordpress.com" --json
```

Output:
```json
{"host":"https://wordpress.com","status_code":200,"detected":true,"matches":[{"name":"WordPress","matched_by":["string_contains:/wp-content/"]}],"timing_ms":188,"redirects":0}
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
- [x] [Laravel](https://laravel.com/)
- [x] [WordPress](https://wordpress.com/)
- [x] [Drupal](https://www.drupal.org/)
- [x] [Lightspeed](https://www.lightspeedhq.nl/)
- [x] [Shopify](https://www.shopify.com/)
- [x] [PrestaShop](https://www.prestashop.com/)
- [x] [Squarespace](https://www.squarespace.com/)
- [x] [Sanity](https://www.sanity.io/)
- [x] [Wix](https://wix.com/)
- [x] [Next](https://nextjs.org/)
- [x] [Microsoft](https://dotnet.microsoft.com/en-us/apps/aspnet)
- [x] [JouwWeb](https://jouwweb.nl/)
- [x] [Magento](https://magento.com/)
- [x] [Weebly](https://www.weebly.com/)
- [x] [Joomla](https://www.joomla.org/)
- [x] [Blogger](https://www.blogger.com/)
- [x] [SilverStripe](https://www.silverstripe.org/)
- [x] Icordis CMS
- [x] [Sulu](https://sulu.io/)
- [x] [Gatsby](https://www.gatsbyjs.com/)
- [x] [Webflow](https://webflow.com/)
- [x] [Zendesk](https://www.zendesk.nl/)
- [x] [Django](https://www.djangoproject.com/)
- [x] [CoreMedia](https://www.coremedia.com/)
- [x] [ProcessWire](https://processwire.com/)
- [x] [TYPO3](https://typo3.org/)
- [x] [Blox](https://bloxcms.com/)
- [x] [Odoo](https://www.odoo.com/)
- [x] [Netifly](https://www.netlify.com/)
- [x] [Amazon S3 (Static Website)](https://aws.amazon.com/)
- [x] [Vercel](https://vercel.com/solutions/web-apps)
- [x] [GitHub Pages](https://docs.github.com/en/pages)
- [x] [Ghost](https://ghost.org/)
- [x] [Craft CMS](https://craftcms.com/)
- [x] [Umbraco](https://umbraco.com/)
- [x] [Sitecore](https://www.sitecore.com/)
- [x] [Strapi](https://strapi.io/)
- [x] [HubSpot CMS](https://www.hubspot.com/products/cms)
- [x] [BigCommerce](https://www.bigcommerce.nl/)
- [x] [Tilda](https://tilda.cc/)
- [x] [Webnode](https://www.webnode.com/)
- [x] [GoDaddy](https://www.godaddy.com/)
- [x] [Adobe](https://www.adobe.com/products/dreamweaver.html)
- [x] [Strato](https://strato.nl/)
- [x] [Google](https://sites.google.com/)
- [x] [Duda](https://www.duda.co/)
- [x] [Nuxt.js](https://nuxt.com/)
- [x] [OpenCart](https://www.opencart.com/)
- [x] [Bitrix (1C-Bitrix)](https://www.1c-bitrix.ru/)
- [x] [Jimdo](https://www.jimdo.com/)
- [x] [Adobe Experience Manager](https://business.adobe.com/products/experience-manager/adobe-experience-manager.html)
- [x] Microsoft Word (generated HTML)
- [x] [Contao](https://contao.org/)
- [x] [IONOS MyWebsite](https://www.ionos.com/websites/website-builder)
- [x] Salesforce Experience Cloud
- [x] [Mobirise](https://mobirise.com/)
- [x] Microsoft FrontPage
- [x] [Adobe Muse](https://www.adobe.com/wam/muse.html)

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
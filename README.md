# CMS-Detector
A Python script to detect the CMS of a specific website.

## Installation
```bash
$ pip3 install virtualenv
$ virtualenv -p python3 .venv
$ source .venv/bin/activate
$ pip3 install -r requirements.txt
$ python3 cms_detector.py -h
```

## Usage
```bash
$ python3 cms_detector.py --host="https://wordpress.com"
[@] Scanning host https://wordpress.com...
[√] CMS is using WordPress!
```

## Support
- [x] Laravel
- [x] WordPress
- [x] Drupal
- [x] Lightspeed
- [x] Shopify
- [x] PrestaShop
- [x] Squarespace
- [x] Sanity
- [x] Wix
- [x] Next.js
- [x] Microsoft ASP
- [x] JouwWeb
- [x] Magento
- [x] Weebly
- [x] Joomla
- [x] Blogger
- [x] SilverStripe CMS
- [x] Icordis CMS
- [x] Sulu CMS
- [x] Gatsby
- [x] Webflow
- [x] Zendesk

## Upcoming
- [ ] Duda
- [ ] GoDaddy
- [ ] Adobe Dreamweaver
- [ ] Strato Website
- [ ] Google Sites
- [ ] Salesforce

## Fingerprint types
- "regex" = Checks regex match in HTML (value=search value)
- "string_contains" = Check HTML if contains value (value=search value)
- "header_key_equals" = Checks for header key (value=match key value)
- "header_key_value" = Checks header key and value match (key=match key value, value=match value)
- "header_key_value_contains" = Checks if header key contains value (key=match key value, value=search value)
- "cookie_key_equals" = Checks for cookie key (value=match key value)
- "cookie_key_value" = Checks cookie key and value match (key=match key value, value=match value)
- "cookie_key_value_contains" = Checks if cookie key contains value (key=match key value, value=search value)
- "cookie_key_value_b64_json_keys" = Checks header key and value its keys after decoding from Base64 and JSON  (key=match key value, value=required keys seperated by |)
- "cookie_substr_key_value_b64_type" = Checks part of header key and value type after decoding from Base64 (length=cut length integer, key=match cut key value, value=match type value)
- "strings_contain" = Check HTML from multiple strings (value=required strings seperated by |)
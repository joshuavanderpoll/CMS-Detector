# CMS-Detector
A Python script to detect CMS fingerprints of a specific website.

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
CMS Detector script
[•] Made by: https://github.com/joshuavanderpoll/CMS-Detector
[@] Scanning host "https://wordpress.com"...
[√] "https://wordpress.com" is using "WordPress"!

$ python3 cms_detector.py --host="https://wordpress.com" --raw
wordpress
```

## Support
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

## Upcoming
- [ ] <a href="https://www.duda.co/" target="_blank">Duda</a>
- [ ] <a href="https://www.godaddy.com/" target="_blank">GoDaddy</a>
- [ ] <a href="https://www.adobe.com/products/dreamweaver.html" target="_blank">Adobe Dreamweaver</a>
- [ ] <a href="https://strato.nl/" target="_blank">Strato Website</a>
- [ ] <a href="https://sites.google.com/" target="_blank">Google Sites</a>
- [ ] <a href="https://www.salesforce.com/" target="_blank">Salesforce</a>

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
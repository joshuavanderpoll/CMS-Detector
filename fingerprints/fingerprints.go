package fingerprints

type CMS struct {
	Name         string        `json:"name"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

type Fingerprint struct {
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Key    string `json:"key,omitempty"`
	Length int    `json:"length,omitempty"`
}

var All = []CMS{
	{
		Name: `WordPress`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator"][content*="WordPress"]`},
			{Type: `html`, Value: `link[href*="/wp-content/"], script[src*="/wp-content/"]`},
			{Type: `html`, Value: `link[href*="/wp-includes/"], script[src*="/wp-includes/"]`},
			{Type: `html`, Value: `link[rel="https://api.w.org/"]`},
		},
	},
	{
		Name: `Shopify`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `X-Shopify-Stage`},
			{Type: `header_key_value_contains`, Value: `https://cdn.shopify.com`, Key: `Link`},
			{Type: `html`, Value: `link[rel="preconnect"][href*="cdn.shopify.com"]`},
			{Type: `html`, Value: `style[data-shopify]`},
		},
	},
	{
		Name: `Laravel`,
		Fingerprints: []Fingerprint{
			{Type: `cookie_key_value_b64_json_keys`, Value: `iv|value|mac`, Key: `XSRF-TOKEN`},
			{Type: `cookie_substr_key_value_b64_type`, Value: `bytes`, Key: `_session`, Length: -8},
		},
	},
	{
		Name: `Drupal`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `X-Drupal-Cache`},
			{Type: `header_key_value_contains`, Value: `Drupal`, Key: `X-Generator`},
			{Type: `html`, Value: `meta[name="generator" i][content*="Drupal" i]`},
			{Type: `html`, Value: `script[src*="/core/misc/drupal.js"], script[src*="/core/misc/drupal.init.js"]`},
			{Type: `html`, Value: `[data-drupal-selector]`},
			{Type: `html`, Value: `[data-drupal-form-fields]`},
			{Type: `html`, Value: `[data-drupal-link-system-path]`},
		},
	},
	{
		Name: `LiteSpeed`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `LiteSpeed`, Key: `Server`},
		},
	},
	{
		Name: `PrestaShop`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `PrestaShop`, Key: `Powered-By`},
			{Type: `html`, Value: `[href*="/modules/prestatemplate/"], [src*="/modules/prestatemplate/"]`},
			{Type: `html`, Value: `a[href="https://www.prestashop.com"][rel*="nofollow"]`},
			{Type: `string_contains`, Value: `var prestashop = {`},
		},
	},
	{
		Name: `SquareSpace`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `SquareSpace`, Key: `Server`},
			{Type: `html`, Value: `link[rel="preconnect"][href*="images.squarespace-cdn.com"]`},
			{Type: `string_contains`, Value: `<!-- this is squarespace. -->`},
			{Type: `string_contains`, Value: `<!-- end of squarespace headers -->`},
		},
	},
	{
		Name: `Sanity`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `link[rel="preconnect"][href*="cdn.sanity.io"]`},
		},
	},
	{
		Name: `Wix`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `X-Wix-Request-ID`},
			{Type: `header_key_value_contains`, Value: `Pepyaka`, Key: `Server`},
		},
	},
	{
		Name: `Microsoft ASP.NET`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `ASP.NET`, Key: `X-Powered-By`},
		},
	},
	{
		Name: `Next.JS`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Next.JS`, Key: `X-Powered-By`},
			{Type: `html`, Value: `script[src*="/_next/static"]`},
		},
	},
	{
		Name: `JouwWeb.nl`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `a[href="https://www.jouwweb.nl"]`},
			{Type: `string_contains`, Value: `window.jouwweb = window.jouwweb`},
			{Type: `string_contains`, Value: `jouwweb.templateConfig = {`},
		},
	},
	{
		Name: `Magento`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `X-Magento-Tags`},
			{Type: `cookie_key_equals`, Value: `X-Magento-Vary`},
			{Type: `html`, Value: `script[type="text/x-magento-init"]`},
		},
	},
	{
		Name: `Weebly`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `weebly.net`, Key: `X-Host`},
			{Type: `string_contains`, Value: `_W.configDomain = "www.weebly.com";`},
		},
	},
	{
		Name: `Ruby on Rails`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `[href*="/rails/active_storage/blobs/"], [src*="/rails/active_storage/blobs/"]`},
		},
	},
	{
		Name: `Joomla`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Joomla" i]`},
		},
	},
	{
		Name: `Blogger`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="blogger" i]`},
			{Type: `html`, Value: `link[rel="dns-prefetch"][href*="blogger.com"]`},
		},
	},
	{
		Name: `ICordis`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Icordis" i]`},
		},
	},
	{
		Name: `SilverStripe`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="SilverStripe" i]`},
		},
	},
	{
		Name: `Sulu`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Sulu/`, Key: `X-Generator`},
		},
	},
	{
		Name: `Express`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Express`, Key: `X-Powered-By`},
		},
	},
	{
		Name: `Gatsby`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Gatsby" i]`},
			{Type: `html`, Value: `script#gatsby-script-loader`},
		},
	},
	{
		Name: `WebFlow`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="webflow" i]`},
			{Type: `html`, Value: `html[data-wf-domain*="webflow."]`},
			{Type: `html`, Value: `[srcset*=".webflow.com"]`},
			{Type: `string_contains`, Value: `<!-- this site was created in webflow`},
		},
	},
	{
		Name: `Zendesk`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `link[rel="preconnect"][href*="assets.zendesk.com"]`},
			{Type: `string_contains`, Value: `function zendeskOpenHelp()`},
		},
	},
	{
		Name: `Django`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `"django_env": "production"`},
		},
	},
	{
		Name: `CoreMedia CMS`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="CoreMedia" i]`},
			{Type: `html`, Value: `meta[name="Classification" i][content*="com.coremedia" i]`},
		},
	},
	{
		Name: `ProcessWire CMS`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `ProcessWire`, Key: `X-Powered-By`},
		},
	},
	{
		Name: `TYPO3`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `[href*="/typo3temp/"], [src*="/typo3temp/"]`},
			{Type: `string_contains`, Value: `This website is powered by TYPO3`},
		},
	},
	{
		Name: `Blox CMS`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `script[src*="bloximages."]`},
			{Type: `string_contains`, Value: `var bloxServiceIDs`},
		},
	},
	{
		Name: `Netlify`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Netlify`, Key: `Server`},
		},
	},
	{
		Name: `Odoo`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Odoo" i]`},
			{Type: `html`, Value: `script[id="web.layout.odooscript"]`},
		},
	},
	{
		Name: `Amazon S3 (Static Website)`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `AmazonS3`, Key: `Server`},
			{Type: `header_key_equals`, Value: `x-amz-id-2`},
			{Type: `header_key_equals`, Value: `x-amz-request-id`},
			{Type: `regex`, Value: `<Error>\s*<Code>NoSuchKey<\/Code>`},
		},
	},
	{
		Name: `Vercel`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `vercel`, Key: `server`},
			{Type: `header_key_equals`, Value: `x-vercel-id`},
			{Type: `header_key_equals`, Value: `x-vercel-cache`},
			{Type: `html`, Value: `meta[name="vercel"]`},
		},
	},
	{
		Name: `GitHub Pages`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `GitHub.com`, Key: `server`},
			{Type: `header_key_equals`, Value: `x-github-request-id`},
			{Type: `header_key_value_contains`, Value: `github`, Key: `x-served-by`},
		},
	},
	{
		Name: `Ghost`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Ghost" i]`},
			{Type: `html`, Value: `script[src*="/public/ghost-sdk"]`},
			{Type: `html`, Value: `[href*="/ghost/api/"], [src*="/ghost/api/"]`},
		},
	},
	{
		Name: `Craft CMS`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Craft CMS`, Key: `x-powered-by`},
			{Type: `header_key_value_contains`, Value: `Craft CMS`, Key: `x-generator`},
			{Type: `cookie_key_equals`, Value: `CraftSessionId`},
		},
	},
	{
		Name: `Umbraco`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `x-umbraco-version`},
			{Type: `html`, Value: `[href*="/umbraco/"], [src*="/umbraco/"]`},
		},
	},
	{
		Name: `Sitecore`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Sitecore`, Key: `x-generator`},
			{Type: `cookie_key_equals`, Value: `SC_ANALYTICS_GLOBAL_COOKIE`},
		},
	},
	{
		Name: `Strapi`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Strapi`, Key: `x-powered-by`},
			{Type: `html`, Value: `meta[name="generator" i][content*="strapi" i]`},
			{Type: `html`, Value: `script[src*="/admin/runtime."]`},
		},
	},
	{
		Name: `HubSpot CMS`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `HubSpot`, Key: `x-powered-by`},
			{Type: `header_key_equals`, Value: `x-hs-cache-config`},
			{Type: `header_key_equals`, Value: `x-hs-cf-cache-control`},
			{Type: `header_key_equals`, Value: `x-hs-cf-cache-status`},
			{Type: `header_key_equals`, Value: `x-hs-cfworker-meta`},
			{Type: `header_key_equals`, Value: `x-hs-content-id`},
			{Type: `header_key_equals`, Value: `x-hs-hub-id`},
			{Type: `header_key_equals`, Value: `x-hs-prerendered`},
			{Type: `html`, Value: `meta[name="generator" i][content*="HubSpot" i]`},
		},
	},
	{
		Name: `BigCommerce`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `bigcommerce.com`, Key: `link`},
			{Type: `cookie_key_equals`, Value: `SHOP_SESSION_TOKEN`},
			{Type: `cookie_key_equals`, Value: `athena_short_visit_id`},
			{Type: `cookie_key_equals`, Value: `fornax_anonymousId`},
			{Type: `cookie_key_equals`, Value: `SF-CSRF-TOKEN`},
			{Type: `string_contains`, Value: `window.stencilBootstrap`},
		},
	},
	{
		Name: `Tilda`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `x-tilda-server`},
			{Type: `header_key_equals`, Value: `x-tilda-imprint`},
			{Type: `html`, Value: `[src*="static.tildacdn.com"]`},
			{Type: `string_contains`, Value: `tilda-blocks`},
		},
	},
	{
		Name: `Webnode`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Webnode" i]`},
		},
	},
	{
		Name: `GoDaddy Website Builder`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `GoDaddy Website Builder`},
			{Type: `string_contains`, Value: `A website created by GoDaddy’s`},
		},
	},
	{
		Name: `Adobe Dreamweaver (static template)`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<!--\s*InstanceBeginEditable`},
			{Type: `regex`, Value: `<!--\s*InstanceEndEditable`},
			{Type: `regex`, Value: `<!-- TemplateBeginEditable`},
		},
	},
	{
		Name: `Strato Website Builder`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `strato-editor`},
			{Type: `string_contains`, Value: `strato-website-builder`},
		},
	},
	{
		Name: `Google Sites`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `docs-prn":"Google Sites"`},
		},
	},
	{
		Name: `Duda`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `[src*="cdn-website.com"], [href*="cdn-website.com"]`},
			{Type: `string_contains`, Value: `dmAPI.runOnReady(`},
			{Type: `string_contains`, Value: `dmAPI.getSiteName(`},
			{Type: `string_contains`, Value: `dmAPI.loadScript(`},
		},
	},
	{
		Name: `Nuxt.js`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `#__nuxt`},
			{Type: `html`, Value: `[href*="/_nuxt/"], [src*="/_nuxt/"]`},
			{Type: `header_key_value_contains`, Value: `Nuxt`, Key: `X-Powered-By`},
		},
	},
	{
		Name: `OpenCart`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="OpenCart" i]`},
			{Type: `html`, Value: `link[href*="/image/catalog/opencart.ico"]`},
			{Type: `cookie_key_equals`, Value: `OCSESSID`},
			{Type: `string_contains`, Value: `OpenCart is open source software and you are free to remove the powered by OpenCart`},
		},
	},
	{
		Name: `Bitrix (1C-Bitrix)`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Bitrix Site Manager`, Key: `X-Powered-CMS`},
			{Type: `cookie_key_equals`, Value: `BITRIX_SM_GUEST_ID`},
			{Type: `cookie_key_equals`, Value: `BITRIX_SM_LAST_VISIT`},
			{Type: `header_key_value_contains`, Value: `policyref="/bitrix/p3p.xml"`, Key: `P3P`},
		},
	},
	{
		Name: `Jimdo`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Jimdo" i]`},
			{Type: `html`, Value: `[src*="assets.jimstatic.com"], [href*="assets.jimstatic.com"]`},
			{Type: `header_key_equals`, Value: `X-Jimdo-Wid`},
		},
	},
	{
		Name: `Adobe Experience Manager`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `[href*="/etc.clientlibs/"], [src*="/etc.clientlibs/"]`},
		},
	},
	{
		Name: `Microsoft Word (generated HTML)`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Microsoft Word" i]`},
		},
	},
	{
		Name: `Contao`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Contao" i]`},
			{Type: `html`, Value: `meta[content*="Contao Open Source CMS"]`},
			{Type: `header_key_equals`, Value: `Contao-Cache`},
		},
	},
	{
		Name: `IONOS MyWebsite`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `[src*="mywebsite-editor.com"], [href*="mywebsite-editor.com"]`},
			{Type: `html`, Value: `[src*="mywebsite-builder.com"], [href*="mywebsite-builder.com"]`},
			{Type: `header_key_value_contains`, Value: `https://*.mywebsite-editor.com`, Key: `Content-Security-Policy`},
		},
	},
	{
		Name: `Salesforce Experience Cloud`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Salesforce" i]`},
			{Type: `header_key_value_contains`, Value: `Salesforce.com`, Key: `Server`},
			{Type: `string_contains`, Value: `LightningOutApp`},
		},
	},
	{
		Name: `Mobirise`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Mobirise" i]`},
			{Type: `html`, Value: `link[href*="assets/mobirise/css/mbr-additional.css"]`},
			{Type: `html`, Value: `[data-app-tag="mobirise"]`},
			{Type: `string_contains`, Value: `Site made with Mobirise Website Builder`},
		},
	},
	{
		Name: `Microsoft FrontPage`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Microsoft FrontPage" i]`},
			{Type: `html`, Value: `meta[content*="FrontPage.Editor.Document"]`},
		},
	},
	{
		Name: `Adobe Muse`,
		Fingerprints: []Fingerprint{
			{Type: `html`, Value: `meta[name="generator" i][content*="Adobe Muse" i]`},
			{Type: `html`, Value: `script[src*="jquery.musemenu.js"]`},
			{Type: `html`, Value: `[data-muse-uid]`},
		},
	},
}

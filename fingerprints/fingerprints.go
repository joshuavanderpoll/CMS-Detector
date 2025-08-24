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
			{Type: `regex`, Value: `<meta name="generator" content="WordPress (.+?)" />`},
			{Type: `string_contains`, Value: `/wp-content/`},
			{Type: `string_contains`, Value: `/wp-json/`},
			{Type: `string_contains`, Value: `/wp-includes/`},
		},
	},
	{
		Name: `Shopify`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `X-Shopify-Stage`},
			{Type: `header_key_value_contains`, Value: `https://cdn.shopify.com`, Key: `Link`},
			{Type: `regex`, Value: `<link rel="preconnect" href="https://cdn\.shopify\.com".*>`},
			{Type: `string_contains`, Value: `<style data-shopify>`},
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
			{Type: `regex`, Value: `<meta name="Generator" content="Drupal (.+?) .*" />`},
			{Type: `regex`, Value: `<script src="/core/misc/drupal\.js\?v=(.+?)"></script>`},
			{Type: `regex`, Value: `<script src="/core/misc/drupal\.init\.js\?v=(.+?)"></script>`},
			{Type: `string_contains`, Value: `data-drupal-selector`},
			{Type: `string_contains`, Value: `data-drupal-form-fields`},
			{Type: `string_contains`, Value: `data-drupal-link-system-path`},
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
			{Type: `string_contains`, Value: `/modules/prestatemplate/`},
			{Type: `string_contains`, Value: `var prestashop = {`},
			{Type: `string_contains`, Value: `<a href="https://www.prestashop.com" target="_blank" rel="noopener noreferrer nofollow">`},
		},
	},
	{
		Name: `SquareSpace`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `SquareSpace`, Key: `Server`},
			{Type: `string_contains`, Value: `<link rel="preconnect" href="https://images.squarespace-cdn.com">`},
			{Type: `string_contains`, Value: `<!-- this is squarespace. -->`},
			{Type: `string_contains`, Value: `<!-- end of squarespace headers -->`},
		},
	},
	{
		Name: `Sanity`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<link rel="preconnect" crossorigin href="https://cdn\.sanity\.io"/>`},
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
			{Type: `string_contains`, Value: `<script src="/_next/static`},
		},
	},
	{
		Name: `JouwWeb.nl`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `powered by <a href="https://www.jouwweb.nl" rel="">jouwweb</a>`},
			{Type: `string_contains`, Value: `window.jouwweb = window.jouwweb`},
			{Type: `string_contains`, Value: `jouwweb.templateConfig = {`},
		},
	},
	{
		Name: `Magento`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_equals`, Value: `X-Magento-Tags`},
			{Type: `cookie_key_equals`, Value: `X-Magento-Vary`},
			{Type: `strings_contain`, Value: `<!--[if lt ie 7]>|<script type="text/javascript">|//<![cdata[|//]]>|</script>|var blank_url =|var blank_img =|<![endif]-->`},
			{Type: `string_contains`, Value: `<script type="text/x-magento-init">`},
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
			{Type: `string_contains`, Value: `/rails/active_storage/blobs/`},
		},
	},
	{
		Name: `Joomla`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name="generator" content="Joomla.*" />`},
		},
	},
	{
		Name: `Blogger`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `<meta content="blogger" name="generator"/>`},
			{Type: `string_contains`, Value: `<link href="//www.blogger.com" rel="dns-prefetch"/>`},
		},
	},
	{
		Name: `ICordis`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name="generator" content="Icordis CMS.*/>`},
		},
	},
	{
		Name: `SilverStripe`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name="generator" content="SilverStripe.*/>`},
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
			{Type: `regex`, Value: `<meta name="generator" content="Gatsby.*/>`},
			{Type: `string_contains`, Value: `<script id="gatsby-script-loader">`},
		},
	},
	{
		Name: `WebFlow`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `<meta content="webflow" name="generator"/>`},
			{Type: `string_contains`, Value: `<!-- this site was created in webflow`},
			{Type: `regex`, Value: `srcset="https://.*\.webflow\.com`},
			{Type: `regex`, Value: `<html data-wf-domain="webflow\..*"`},
		},
	},
	{
		Name: `Zendesk`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `function zendeskOpenHelp()`},
			{Type: `string_contains`, Value: `<link rel="preconnect" href="https://assets.zendesk.com"`},
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
			{Type: `regex`, Value: `<meta name="generator" content="CoreMedia.*">`},
			{Type: `regex`, Value: `<meta name="Classification" content="com\.coremedia\..*">`},
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
			{Type: `string_contains`, Value: `This website is powered by TYPO3`},
			{Type: `string_contains`, Value: `href="/typo3temp/`},
		},
	},
	{
		Name: `Blox CMS`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<script.*src="https://bloximages\..*>`},
			{Type: `string_contains`, Value: `var bloxServiceIDs`},
			{Type: `string_contains`, Value: `bloxServiceIDs.push();`},
		},
	},
	{
		Name: `Netifly`,
		Fingerprints: []Fingerprint{
			{Type: `header_key_value_contains`, Value: `Netlify`, Key: `Server`},
		},
	},
	{
		Name: `Odoo`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `<meta name="generator" content="Odoo"/>`},
			{Type: `regex`, Value: `<script.*id="web.layout.odooscript".*>`},
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
			{Type: `string_contains`, Value: `<meta name="vercel" content=`},
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
			{Type: `regex`, Value: `<meta name="generator" content="Ghost ?([0-9]+\.[0-9]+.*?)"\s*\/?>(?i)`},
			{Type: `string_contains`, Value: `/ghost/api/`},
			{Type: `string_contains`, Value: `<script src="/public/ghost-sdk`},
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
			{Type: `string_contains`, Value: `href="/umbraco/`},
			{Type: `string_contains`, Value: `src="/umbraco/`},
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
			{Type: `regex`, Value: `<meta name="generator" content="strapi"\s*/?>`},
			{Type: `string_contains`, Value: `/admin/runtime.`},
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
			{Type: `regex`, Value: `<meta name="generator" content="HubSpot.*"\s*/?>`},
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
			{Type: `regex`, Value: `src=\"https:\/\/static\.tildacdn\.com\/.*\"`},
			{Type: `string_contains`, Value: `tilda-blocks`},
		},
	},
	{
		Name: `Webnode`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name="generator" content="Webnode .*"\s*/?>`},
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
			{Type: `string_contains`, Value: `dmAPI.runOnReady(`},
			{Type: `string_contains`, Value: `dmAPI.getSiteName(`},
			{Type: `string_contains`, Value: `dmAPI.loadScript(`},
			{Type: `regex`, Value: `https?://(?:static|irp|lirp)\.cdn-website\.com/`},
		},
	},
	{
		Name: `Nuxt.js`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `id="__nuxt"`},
			{Type: `string_contains`, Value: `/_nuxt/`},
			{Type: `header_key_value_contains`, Value: `Nuxt`, Key: `X-Powered-By`},
		},
	},
	{
		Name: `OpenCart`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name=\"generator\" content=\"OpenCart.*\"\s*/?>`},
			{Type: `string_contains`, Value: `/image/catalog/opencart.ico`},
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
			{Type: `regex`, Value: `<meta name=\"generator\" content=\"Jimdo Creator.*\"\s*/?>`},
			{Type: `regex`, Value: `https?://assets\.jimstatic\.com/`},
			{Type: `header_key_equals`, Value: `X-Jimdo-Wid`},
		},
	},
	{
		Name: `Adobe Experience Manager`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `/etc.clientlibs/`},
			{Type: `regex`, Value: `/etc\.clientlibs/(?:granite|foundation)/`},
		},
	},
	{
		Name: `Microsoft Word (generated HTML)`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name=\"Generator\" content=\"Microsoft Word.*\">`},
		},
	},
	{
		Name: `Contao`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name=\"generator\" content=\"Contao.*\"\s*/?>`},
			{Type: `string_contains`, Value: `content="Contao Open Source CMS"`},
			{Type: `header_key_equals`, Value: `Contao-Cache`},
		},
	},
	{
		Name: `IONOS MyWebsite`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `https?://(?:assets\.)?mywebsite-?editor\.com/`},
			{Type: `regex`, Value: `https?://.*\.mywebsite-?builder\.com/`},
			{Type: `header_key_value_contains`, Value: `https://*.mywebsite-editor.com`, Key: `Content-Security-Policy`},
		},
	},
	{
		Name: `Salesforce Experience Cloud`,
		Fingerprints: []Fingerprint{
			{Type: `string_contains`, Value: `LightningOutApp`},
			{Type: `regex`, Value: `<meta name=\"generator\" content=\"Salesforce.*\"\s*/?>`},
			{Type: `header_key_value_contains`, Value: `Salesforce.com`, Key: `Server`},
		},
	},
	{
		Name: `Mobirise`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name=\"generator\" content=\"Mobirise.*\"\s*/?>`},
			{Type: `string_contains`, Value: `assets/mobirise/css/mbr-additional.css`},
			{Type: `string_contains`, Value: `data-app-tag="mobirise"`},
			{Type: `string_contains`, Value: `Site made with Mobirise Website Builder`},
		},
	},
	{
		Name: `Microsoft FrontPage`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name=\"GENERATOR\" content=\"Microsoft FrontPage.*\">`},
			{Type: `string_contains`, Value: `content="Microsoft FrontPage`},
			{Type: `string_contains`, Value: `content="FrontPage.Editor.Document"`},
		},
	},
	{
		Name: `Adobe Muse`,
		Fingerprints: []Fingerprint{
			{Type: `regex`, Value: `<meta name=\"generator\" content=\"Adobe Muse.*\"\s*/?>`},
			{Type: `string_contains`, Value: `jquery.musemenu.js`},
			{Type: `string_contains`, Value: `data-muse-uid=`},
		},
	},
}

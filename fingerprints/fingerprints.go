package fingerprints

var Data = []byte(`[
    {
        "name": "WordPress",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"WordPress (.+?)\" />"
            },
            {
                "type": "string_contains",
                "value": "/wp-content/"
            },
            {
                "type": "string_contains",
                "value": "/wp-json/"
            },
            {
                "type": "string_contains",
                "value": "/wp-includes/"
            }
        ]
    },
    {
        "name": "Shopify",
        "fingerprints": [
            {
                "type": "header_key_equals",
                "value": "X-Shopify-Stage"
            },
            {
                "type": "header_key_value_contains",
                "key": "Link",
                "value": "https://cdn.shopify.com"
            },
            {
                "type": "regex",
                "value": "<link rel=\"preconnect\" href=\"https://cdn\\.shopify\\.com\".*>"
            },
            {
                "type": "string_contains",
                "value": "<style data-shopify>"
            }
        ]
    },
    {
        "name": "Laravel",
        "fingerprints": [
            {
                "type": "cookie_key_value_b64_json_keys",
                "key": "XSRF-TOKEN",
                "value": "iv|value|mac"
            },
            {
                "type": "cookie_substr_key_value_b64_type",
                "length": -8,
                "key": "_session",
                "value": "bytes"
            }
        ]
    },
    {
        "name": "Drupal",
        "fingerprints": [
            {
                "type": "header_key_equals",
                "value": "X-Drupal-Cache"
            },
            {
                "type": "header_key_value_contains",
                "key": "X-Generator",
                "value": "Drupal"
            },
            {
                "type": "regex",
                "value": "<meta name=\"Generator\" content=\"Drupal (.+?) .*\" />"
            },
            {
                "type": "regex",
                "value": "<script src=\"/core/misc/drupal\\.js\\?v=(.+?)\"></script>"
            },
            {
                "type": "regex",
                "value": "<script src=\"/core/misc/drupal\\.init\\.js\\?v=(.+?)\"></script>"
            },
            {
                "type": "string_contains",
                "value": "data-drupal-selector"
            },
            {
                "type": "string_contains",
                "value": "data-drupal-form-fields"
            },
            {
                "type": "string_contains",
                "value": "data-drupal-link-system-path"
            }
        ]
    },
    {
        "name": "LiteSpeed",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "Server",
                "value": "LiteSpeed"
            }
        ]
    },
    {
        "name": "PrestaShop",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "Powered-By",
                "value": "PrestaShop"
            },
            {
                "type": "string_contains",
                "value": "/modules/prestatemplate/"
            },
            {
                "type": "string_contains",
                "value": "var prestashop = {"
            },
            {
                "type": "string_contains",
                "value": "<a href=\"https://www.prestashop.com\" target=\"_blank\" rel=\"noopener noreferrer nofollow\">"
            }
        ]
    },
    {
        "name": "SquareSpace",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "Server",
                "value": "SquareSpace"
            },
            {
                "type": "string_contains",
                "value": "<link rel=\"preconnect\" href=\"https://images.squarespace-cdn.com\">"
            },
            {
                "type": "string_contains",
                "value": "<!-- this is squarespace. -->"
            },
            {
                "type": "string_contains",
                "value": "<!-- end of squarespace headers -->"
            }
        ]
    },
    {
        "name": "Sanity",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<link rel=\"preconnect\" crossorigin href=\"https://cdn\\.sanity\\.io\"/>"
            }
        ]
    },
    {
        "name": "Wix",
        "fingerprints": [
            {
                "type": "header_key_equals",
                "value": "X-Wix-Request-ID"
            },
            {
                "type": "header_key_value_contains",
                "key": "Server",
                "value": "Pepyaka"
            }
        ]
    },
    {
        "name": "Microsoft ASP.NET",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Powered-By",
                "value": "ASP.NET"
            }
        ]
    },
    {
        "name": "Next.JS",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Powered-By",
                "value": "Next.JS"
            },
            {
                "type": "string_contains",
                "value": "<script src=\"/_next/static"
            }
        ]
    },
    {
        "name": "JouwWeb.nl",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "powered by <a href=\"https://www.jouwweb.nl\" rel=\"\">jouwweb</a>"
            },
            {
                "type": "string_contains",
                "value": "window.jouwweb = window.jouwweb"
            },
            {
                "type": "string_contains",
                "value": "jouwweb.templateConfig = {"
            }
        ]
    },
    {
        "name": "Magento",
        "fingerprints": [
            {
                "type": "header_key_equals",
                "value": "X-Magento-Tags"
            },
            {
                "type": "cookie_key_equals",
                "value": "X-Magento-Vary"
            },
            {
                "type": "strings_contain",
                "value": "<!--[if lt ie 7]>|<script type=\"text/javascript\">|//<![cdata[|//]]>|</script>|var blank_url =|var blank_img =|<![endif]-->"
            },
            {
                "type": "string_contains",
                "value": "<script type=\"text/x-magento-init\">"
            }
        ]
    },
    {
        "name": "Weebly",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Host",
                "value": "weebly.net"
            },
            {
                "type": "string_contains",
                "value": "_W.configDomain = \"www.weebly.com\";"
            }
        ]
    },
    {
        "name": "Ruby on Rails",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "/rails/active_storage/blobs/"
            }
        ]
    },
    {
        "name": "Joomla",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"Joomla.*\" />"
            }
        ]
    },
    {
        "name": "Blogger",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "<meta content=\"blogger\" name=\"generator\"/>"
            },
            {
                "type": "string_contains",
                "value": "<link href=\"//www.blogger.com\" rel=\"dns-prefetch\"/>"
            }
        ]
    },
    {
        "name": "ICordis",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"Icordis CMS.*/>"
            }
        ]
    },
    {
        "name": "SilverStripe",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"SilverStripe.*/>"
            }
        ]
    },
    {
        "name": "Sulu",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Generator",
                "value": "Sulu/"
            }
        ]
    },
    {
        "name": "Express",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Powered-By",
                "value": "Express"
            }
        ]
    },
    {
        "name": "Gatsby",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"Gatsby.*/>"
            },
            {
                "type": "string_contains",
                "value": "<script id=\"gatsby-script-loader\">"
            }
        ]
    },
    {
        "name": "WebFlow",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "<meta content=\"webflow\" name=\"generator\"/>"
            },
            {
                "type": "string_contains",
                "value": "<!-- this site was created in webflow"
            },
            {
                "type": "regex",
                "value": "srcset=\"https://.*\\.webflow\\.com"
            },
            {
                "type": "regex",
                "value": "<html data-wf-domain=\"webflow\\..*\""
            }
        ]
    },
    {
        "name": "Zendesk",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "function zendeskOpenHelp()"
            },
            {
                "type": "string_contains",
                "value": "<link rel=\"preconnect\" href=\"https://assets.zendesk.com\""
            }
        ]
    },
    {
        "name": "Django",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "\"django_env\": \"production\""
            }
        ]
    },
    {
        "name": "CoreMedia CMS",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"CoreMedia.*\">"
            },
            {
                "type": "regex",
                "value": "<meta name=\"Classification\" content=\"com\\.coremedia\\..*\">"
            }
        ]
    },
    {
        "name": "ProcessWire CMS",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Powered-By",
                "value": "ProcessWire"
            }
        ]
    },
    {
        "name": "TYPO3",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "This website is powered by TYPO3"
            },
            {
                "type": "string_contains",
                "value": "href=\"/typo3temp/"
            }
        ]
    },
    {
        "name": "Blox CMS",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<script.*src=\"https://bloximages\\..*>"
            },
            {
                "type": "string_contains",
                "value": "var bloxServiceIDs"
            },
            {
                "type": "string_contains",
                "value": "bloxServiceIDs.push();"
            }
        ]
    },
    {
        "name": "Netifly",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "Server",
                "value": "Netlify"
            }
        ]
    },
    {
        "name": "Odoo",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "<meta name=\"generator\" content=\"Odoo\"/>"
            },
            {
                "type": "regex",
                "value": "<script.*id=\"web.layout.odooscript\".*>"
            }
        ]
    },
    {
        "name": "Amazon S3 (Static Website)",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "Server",
                "value": "AmazonS3"
            },
            {
                "type": "header_key_equals",
                "value": "x-amz-id-2"
            },
            {
                "type": "header_key_equals",
                "value": "x-amz-request-id"
            },
            {
                "type": "regex",
                "value": "<Error>\\s*<Code>NoSuchKey<\\/Code>"
            }
        ]
    },
    {
        "name": "Vercel",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "server",
                "value": "vercel"
            },
            {
                "type": "header_key_equals",
                "value": "x-vercel-id"
            },
            {
                "type": "header_key_equals",
                "value": "x-vercel-cache"
            },
            {
                "type": "string_contains",
                "value": "<meta name=\"vercel\" content="
            }
        ]
    },
    {
        "name": "GitHub Pages",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "server",
                "value": "GitHub.com"
            },
            {
                "type": "header_key_equals",
                "value": "x-github-request-id"
            },
            {
                "type": "header_key_value_contains",
                "key": "x-served-by",
                "value": "github"
            }
        ]
    },
    {
        "name": "Ghost",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"Ghost ?([0-9]+\\.[0-9]+.*?)\"\\s*\\/?>(?i)"
            },
            {
                "type": "string_contains",
                "value": "/ghost/api/"
            },
            {
                "type": "string_contains",
                "value": "<script src=\"/public/ghost-sdk"
            }
        ]
    },
    {
        "name": "Craft CMS",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "x-powered-by",
                "value": "Craft CMS"
            },
            {
                "type": "header_key_value_contains",
                "key": "x-generator",
                "value": "Craft CMS"
            },
            {
                "type": "cookie_key_equals",
                "value": "CraftSessionId"
            }
        ]
    },
    {
        "name": "Umbraco",
        "fingerprints": [
            {
                "type": "header_key_equals",
                "value": "x-umbraco-version"
            },
            {
                "type": "string_contains",
                "value": "href=\"/umbraco/"
            },
            {
                "type": "string_contains",
                "value": "src=\"/umbraco/"
            }
        ]
    },
    {
        "name": "Sitecore",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "x-generator",
                "value": "Sitecore"
            },
            {
                "type": "cookie_key_equals",
                "value": "SC_ANALYTICS_GLOBAL_COOKIE"
            }
        ]
    },
    {
        "name": "Strapi",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "x-powered-by",
                "value": "Strapi"
            },
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"strapi\"\\s*/?>"
            },
            {
                "type": "string_contains",
                "value": "/admin/runtime."
            }
        ]
    },
    {
        "name": "HubSpot CMS",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "x-powered-by",
                "value": "HubSpot"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-cache-config"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-cf-cache-control"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-cf-cache-status"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-cfworker-meta"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-content-id"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-hub-id"
            },
            {
                "type": "header_key_equals",
                "value": "x-hs-prerendered"
            },
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"HubSpot.*\"\\s*/?>"
            }
        ]
    },
    {
        "name": "BigCommerce",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "link",
                "value": "bigcommerce.com"
            },
            {
                "type": "cookie_key_equals",
                "value": "SHOP_SESSION_TOKEN"
            },
            {
                "type": "cookie_key_equals",
                "value": "athena_short_visit_id"
            },
            {
                "type": "cookie_key_equals",
                "value": "fornax_anonymousId"
            },
            {
                "type": "cookie_key_equals",
                "value": "SF-CSRF-TOKEN"
            },
            {
                "type": "string_contains",
                "value": "window.stencilBootstrap"
            }
        ]
    },
    {
        "name": "Tilda",
        "fingerprints": [
            {
                "type": "header_key_equals",
                "value": "x-tilda-server"
            },
            {
                "type": "header_key_equals",
                "value": "x-tilda-imprint"
            },
            {
                "type": "regex",
                "value": "src=\\\"https:\\/\\/static\\.tildacdn\\.com\\/.*\\\""
            },
            {
                "type": "string_contains",
                "value": "tilda-blocks"
            }
        ]
    },
    {
        "name": "Webnode",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\"generator\" content=\"Webnode .*\"\\s*/?>"
            }
        ]
    },
    {
        "name": "GoDaddy Website Builder",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "GoDaddy Website Builder"
            },
            {
                "type": "string_contains",
                "value": "A website created by GoDaddy’s"
            }
        ]
    },
    {
        "name": "Adobe Dreamweaver (static template)",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<!--\\s*InstanceBeginEditable"
            },
            {
                "type": "regex",
                "value": "<!--\\s*InstanceEndEditable"
            },
            {
                "type": "regex",
                "value": "<!-- TemplateBeginEditable"
            }
        ]
    },
    {
        "name": "Strato Website Builder",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "strato-editor"
            },
            {
                "type": "string_contains",
                "value": "strato-website-builder"
            }
        ]
    },
    {
        "name": "Google Sites",
        "fingerprints": [
            {
                "type": "regex",
                "value": "docs-prn\":\"Google Sites\""
            }
        ]
    },
    {
        "name": "Duda",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "dmAPI.runOnReady("
            },
            {
                "type": "string_contains",
                "value": "dmAPI.getSiteName("
            },
            {
                "type": "string_contains",
                "value": "dmAPI.loadScript("
            },
            {
                "type": "regex",
                "value": "https?://(?:static|irp|lirp)\\.cdn-website\\.com/"
            }
        ]
    },
    {
        "name": "Nuxt.js",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "id=\"__nuxt\""
            },
            {
                "type": "string_contains",
                "value": "/_nuxt/"
            },
            {
                "type": "header_key_value_contains",
                "key": "X-Powered-By",
                "value": "Nuxt"
            }
        ]
    },
    {
        "name": "OpenCart",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"generator\\\" content=\\\"OpenCart.*\\\"\\s*/?>"
            },
            {
                "type": "string_contains",
                "value": "/image/catalog/opencart.ico"
            },
            {
                "type": "cookie_key_equals",
                "value": "OCSESSID"
            },
            {
                "type": "string_contains",
                "value": "OpenCart is open source software and you are free to remove the powered by OpenCart"
            }
        ]
    },
    {
        "name": "Bitrix (1C-Bitrix)",
        "fingerprints": [
            {
                "type": "header_key_value_contains",
                "key": "X-Powered-CMS",
                "value": "Bitrix Site Manager"
            },
            {
                "type": "cookie_key_equals",
                "value": "BITRIX_SM_GUEST_ID"
            },
            {
                "type": "cookie_key_equals",
                "value": "BITRIX_SM_LAST_VISIT"
            },
            {
                "type": "header_key_value_contains",
                "key": "P3P",
                "value": "policyref=\"/bitrix/p3p.xml\""
            }
        ]
    },
    {
        "name": "Jimdo",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"generator\\\" content=\\\"Jimdo Creator.*\\\"\\s*/?>"
            },
            {
                "type": "regex",
                "value": "https?://assets\\.jimstatic\\.com/"
            },
            {
                "type": "header_key_equals",
                "value": "X-Jimdo-Wid"
            }
        ]
    },
    {
        "name": "Adobe Experience Manager",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "/etc.clientlibs/"
            },
            {
                "type": "regex",
                "value": "/etc\\.clientlibs/(?:granite|foundation)/"
            }
        ]
    },
    {
        "name": "Microsoft Word (generated HTML)",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"Generator\\\" content=\\\"Microsoft Word.*\\\">"
            }
        ]
    },
    {
        "name": "Contao",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"generator\\\" content=\\\"Contao.*\\\"\\s*/?>"
            },
            {
                "type": "string_contains",
                "value": "content=\"Contao Open Source CMS\""
            },
            {
                "type": "header_key_equals",
                "value": "Contao-Cache"
            }
        ]
    },
    {
        "name": "IONOS MyWebsite",
        "fingerprints": [
            {
                "type": "regex",
                "value": "https?://(?:assets\\.)?mywebsite-?editor\\.com/"
            },
            {
                "type": "regex",
                "value": "https?://.*\\.mywebsite-?builder\\.com/"
            },
            {
                "type": "header_key_value_contains",
                "key": "Content-Security-Policy",
                "value": "https://*.mywebsite-editor.com"
            }
        ]
    },
    {
        "name": "Salesforce Experience Cloud",
        "fingerprints": [
            {
                "type": "string_contains",
                "value": "LightningOutApp"
            },
            {
                "type": "regex",
                "value": "<meta name=\\\"generator\\\" content=\\\"Salesforce.*\\\"\\s*/?>"
            },
            {
                "type": "header_key_value_contains",
                "key": "Server",
                "value": "Salesforce.com"
            }
        ]
    },
    {
        "name": "Mobirise",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"generator\\\" content=\\\"Mobirise.*\\\"\\s*/?>"
            },
            {
                "type": "string_contains",
                "value": "assets/mobirise/css/mbr-additional.css"
            },
            {
                "type": "string_contains",
                "value": "data-app-tag=\"mobirise\""
            },
            {
                "type": "string_contains",
                "value": "Site made with Mobirise Website Builder"
            }
        ]
    },
    {
        "name": "Microsoft FrontPage",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"GENERATOR\\\" content=\\\"Microsoft FrontPage.*\\\">"
            },
            {
                "type": "string_contains",
                "value": "content=\"Microsoft FrontPage"
            },
            {
                "type": "string_contains",
                "value": "content=\"FrontPage.Editor.Document\""
            }
        ]
    },
    {
        "name": "Adobe Muse",
        "fingerprints": [
            {
                "type": "regex",
                "value": "<meta name=\\\"generator\\\" content=\\\"Adobe Muse.*\\\"\\s*/?>"
            },
            {
                "type": "string_contains",
                "value": "jquery.musemenu.js"
            },
            {
                "type": "string_contains",
                "value": "data-muse-uid="
            }
        ]
    }
]`)

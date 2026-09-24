/**
 * §31.2 brand list — commonly impersonated brands with their legitimate
 * domains and known aliases. Versioned with SCANNER_VERSION.
 *
 * The spec targets "roughly 500"; this curated first version has ~200
 * entries covering the most-phished categories (finance, cloud, social,
 * shipping, commerce, government, telecom, security). It is deliberately
 * conservative: an incomplete `domains` list is the main source of false
 * positives ("a domain on the brand list matching itself, or matching one
 * of its declared aliases, never fires"), so every domain here is one the
 * brand actually operates.
 *
 * `fuzzy: false` marks brands whose token is an ordinary word ("target",
 * "apple", "discover") — edit-distance matching on those would flag honest
 * sites (ample.com, targets.com). They are still matched by the stronger
 * techniques (homoglyphs, brand + login keyword, brand domain inside a
 * subdomain).
 */
export interface Brand {
  name: string;
  /** Lowercase ASCII token looked for in candidate domains. */
  token: string;
  /** Domains the brand legitimately operates — a host under any of these never matches. */
  domains: readonly string[];
  fuzzy?: boolean;
  category: 'finance' | 'crypto' | 'tech' | 'social' | 'gaming' | 'shipping' | 'commerce' | 'government' | 'telecom' | 'security' | 'media';
}

export const BRANDS: readonly Brand[] = [
  // ---- finance -----------------------------------------------------------
  { name: 'PayPal', token: 'paypal', category: 'finance', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com', 'braintreegateway.com', 'venmo.com'] },
  { name: 'Venmo', token: 'venmo', category: 'finance', domains: ['venmo.com', 'paypal.com'] },
  { name: 'Stripe', token: 'stripe', category: 'finance', fuzzy: false, domains: ['stripe.com', 'stripe.network'] },
  { name: 'Chase', token: 'chase', category: 'finance', fuzzy: false, domains: ['chase.com', 'jpmorganchase.com', 'jpmorgan.com'] },
  { name: 'Bank of America', token: 'bankofamerica', category: 'finance', domains: ['bankofamerica.com', 'bofa.com', 'ml.com'] },
  { name: 'Wells Fargo', token: 'wellsfargo', category: 'finance', domains: ['wellsfargo.com', 'wf.com'] },
  { name: 'Citibank', token: 'citibank', category: 'finance', domains: ['citi.com', 'citibank.com', 'citigroup.com'] },
  { name: 'Capital One', token: 'capitalone', category: 'finance', domains: ['capitalone.com'] },
  { name: 'American Express', token: 'americanexpress', category: 'finance', domains: ['americanexpress.com', 'amex.com', 'aexp.com'] },
  { name: 'Discover', token: 'discover', category: 'finance', fuzzy: false, domains: ['discover.com'] },
  { name: 'U.S. Bank', token: 'usbank', category: 'finance', domains: ['usbank.com'] },
  { name: 'TD Bank', token: 'tdbank', category: 'finance', domains: ['td.com', 'tdbank.com'] },
  { name: 'Charles Schwab', token: 'schwab', category: 'finance', domains: ['schwab.com'] },
  { name: 'Fidelity', token: 'fidelity', category: 'finance', fuzzy: false, domains: ['fidelity.com', 'fidelity.co.uk'] },
  { name: 'Vanguard', token: 'vanguard', category: 'finance', fuzzy: false, domains: ['vanguard.com'] },
  { name: 'Robinhood', token: 'robinhood', category: 'finance', fuzzy: false, domains: ['robinhood.com'] },
  { name: 'E*TRADE', token: 'etrade', category: 'finance', domains: ['etrade.com'] },
  { name: 'HSBC', token: 'hsbc', category: 'finance', domains: ['hsbc.com', 'hsbc.co.uk', 'hsbc.co.in', 'us.hsbc.com'] },
  { name: 'Barclays', token: 'barclays', category: 'finance', domains: ['barclays.co.uk', 'barclays.com', 'barclaycard.co.uk'] },
  { name: 'Santander', token: 'santander', category: 'finance', domains: ['santander.co.uk', 'santander.com', 'santanderbank.com'] },
  { name: 'Lloyds Bank', token: 'lloydsbank', category: 'finance', domains: ['lloydsbank.com', 'lloyds.com'] },
  { name: 'NatWest', token: 'natwest', category: 'finance', domains: ['natwest.com'] },
  { name: 'Halifax', token: 'halifax', category: 'finance', fuzzy: false, domains: ['halifax.co.uk'] },
  { name: 'Revolut', token: 'revolut', category: 'finance', domains: ['revolut.com'] },
  { name: 'Wise', token: 'transferwise', category: 'finance', domains: ['wise.com', 'transferwise.com'] },
  { name: 'Monzo', token: 'monzo', category: 'finance', domains: ['monzo.com'] },
  { name: 'Visa', token: 'visa', category: 'finance', fuzzy: false, domains: ['visa.com'] },
  { name: 'Mastercard', token: 'mastercard', category: 'finance', domains: ['mastercard.com', 'mastercard.us'] },
  { name: 'Cash App', token: 'cashapp', category: 'finance', domains: ['cash.app', 'cashapp.com', 'square.com', 'squareup.com'] },
  { name: 'Zelle', token: 'zelle', category: 'finance', domains: ['zellepay.com', 'zelle.com'] },
  { name: 'Western Union', token: 'westernunion', category: 'finance', domains: ['westernunion.com', 'wu.com'] },
  { name: 'MoneyGram', token: 'moneygram', category: 'finance', domains: ['moneygram.com'] },
  { name: 'State Bank of India', token: 'onlinesbi', category: 'finance', domains: ['onlinesbi.sbi', 'sbi.co.in', 'onlinesbi.com'] },
  { name: 'HDFC Bank', token: 'hdfcbank', category: 'finance', domains: ['hdfcbank.com', 'hdfc.com'] },
  { name: 'ICICI Bank', token: 'icicibank', category: 'finance', domains: ['icicibank.com'] },
  { name: 'Axis Bank', token: 'axisbank', category: 'finance', domains: ['axisbank.com'] },
  { name: 'Kotak Mahindra Bank', token: 'kotak', category: 'finance', domains: ['kotak.com'] },
  { name: 'Paytm', token: 'paytm', category: 'finance', domains: ['paytm.com'] },
  { name: 'PhonePe', token: 'phonepe', category: 'finance', domains: ['phonepe.com'] },
  { name: 'Razorpay', token: 'razorpay', category: 'finance', domains: ['razorpay.com'] },
  { name: 'Intuit', token: 'intuit', category: 'finance', domains: ['intuit.com', 'quickbooks.com', 'turbotax.com', 'mint.com'] },
  { name: 'TurboTax', token: 'turbotax', category: 'finance', domains: ['turbotax.com', 'intuit.com'] },
  { name: 'QuickBooks', token: 'quickbooks', category: 'finance', domains: ['quickbooks.com', 'intuit.com'] },
  { name: 'Klarna', token: 'klarna', category: 'finance', domains: ['klarna.com'] },
  { name: 'Afterpay', token: 'afterpay', category: 'finance', domains: ['afterpay.com'] },
  { name: 'Affirm', token: 'affirm', category: 'finance', fuzzy: false, domains: ['affirm.com'] },
  { name: 'Payoneer', token: 'payoneer', category: 'finance', domains: ['payoneer.com'] },
  { name: 'Skrill', token: 'skrill', category: 'finance', domains: ['skrill.com'] },
  { name: 'Alipay', token: 'alipay', category: 'finance', domains: ['alipay.com'] },
  { name: 'Deutsche Bank', token: 'deutschebank', category: 'finance', domains: ['db.com', 'deutsche-bank.de'] },
  { name: 'BNP Paribas', token: 'bnpparibas', category: 'finance', domains: ['bnpparibas.com', 'bnpparibas.fr'] },
  { name: 'Rabobank', token: 'rabobank', category: 'finance', domains: ['rabobank.nl', 'rabobank.com'] },
  { name: 'Commonwealth Bank', token: 'commbank', category: 'finance', domains: ['commbank.com.au'] },
  { name: 'Westpac', token: 'westpac', category: 'finance', domains: ['westpac.com.au'] },
  { name: 'RBC Royal Bank', token: 'rbcroyalbank', category: 'finance', domains: ['rbc.com', 'rbcroyalbank.com'] },
  { name: 'Scotiabank', token: 'scotiabank', category: 'finance', domains: ['scotiabank.com'] },
  { name: 'Interac', token: 'interac', category: 'finance', domains: ['interac.ca'] },

  // ---- crypto --------------------------------------------------------------
  { name: 'Coinbase', token: 'coinbase', category: 'crypto', domains: ['coinbase.com'] },
  { name: 'Binance', token: 'binance', category: 'crypto', domains: ['binance.com', 'binance.us'] },
  { name: 'Kraken', token: 'kraken', category: 'crypto', fuzzy: false, domains: ['kraken.com'] },
  { name: 'Blockchain.com', token: 'blockchain', category: 'crypto', fuzzy: false, domains: ['blockchain.com'] },
  { name: 'MetaMask', token: 'metamask', category: 'crypto', domains: ['metamask.io'] },
  { name: 'Ledger', token: 'ledger', category: 'crypto', fuzzy: false, domains: ['ledger.com'] },
  { name: 'Trezor', token: 'trezor', category: 'crypto', domains: ['trezor.io'] },
  { name: 'OpenSea', token: 'opensea', category: 'crypto', domains: ['opensea.io'] },
  { name: 'Phantom', token: 'phantom', category: 'crypto', fuzzy: false, domains: ['phantom.app', 'phantom.com'] },
  { name: 'Uniswap', token: 'uniswap', category: 'crypto', domains: ['uniswap.org'] },

  // ---- tech / cloud --------------------------------------------------------
  { name: 'Google', token: 'google', category: 'tech', domains: ['google.com', 'google.co.uk', 'google.co.in', 'google.de', 'google.fr', 'google.ca', 'google.com.au', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'withgoogle.com', 'g.co', 'goo.gl', 'google.dev', 'blog.google', 'googlemail.com', 'googlevideo.com'] },
  { name: 'Gmail', token: 'gmail', category: 'tech', domains: ['gmail.com', 'google.com'] },
  { name: 'YouTube', token: 'youtube', category: 'media', domains: ['youtube.com', 'youtu.be', 'ytimg.com', 'youtube-nocookie.com'] },
  { name: 'Microsoft', token: 'microsoft', category: 'tech', domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoft365.com', 'windows.com', 'windows.net', 'azure.com', 'bing.com', 'msn.com', 'skype.com', 'xbox.com', 'sharepoint.com', 'onedrive.com', 'hotmail.com', 'msft.net', 'windowsupdate.com', 'microsoftstore.com', 'msauth.net', 'msftauth.net'] },
  { name: 'Outlook', token: 'outlook', category: 'tech', fuzzy: false, domains: ['outlook.com', 'live.com', 'microsoft.com', 'office.com'] },
  { name: 'Office 365', token: 'office365', category: 'tech', domains: ['office.com', 'office365.com', 'microsoft.com', 'microsoftonline.com'] },
  { name: 'OneDrive', token: 'onedrive', category: 'tech', domains: ['onedrive.com', 'live.com', 'microsoft.com', 'sharepoint.com'] },
  { name: 'SharePoint', token: 'sharepoint', category: 'tech', domains: ['sharepoint.com', 'microsoft.com'] },
  { name: 'Hotmail', token: 'hotmail', category: 'tech', domains: ['hotmail.com', 'outlook.com', 'live.com'] },
  { name: 'Azure', token: 'azure', category: 'tech', fuzzy: false, domains: ['azure.com', 'azure.net', 'windows.net', 'microsoft.com', 'azurewebsites.net'] },
  { name: 'Apple', token: 'apple', category: 'tech', fuzzy: false, domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com', 'apple.co', 'itunes.com', 'apple.news', 'cdn-apple.com'] },
  { name: 'iCloud', token: 'icloud', category: 'tech', domains: ['icloud.com', 'apple.com', 'icloud-content.com'] },
  { name: 'iTunes', token: 'itunes', category: 'tech', domains: ['itunes.com', 'apple.com'] },
  { name: 'Amazon', token: 'amazon', category: 'commerce', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.co.jp', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.com.au', 'amazon.com.br', 'amazon.com.mx', 'amazon.nl', 'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazonaws.com', 'amazon.jobs', 'a2z.com', 'media-amazon.com', 'ssl-images-amazon.com', 'amzn.to', 'amazonpay.com', 'amazon.dev', 'primevideo.com', 'audible.com'] },
  { name: 'Prime Video', token: 'primevideo', category: 'media', domains: ['primevideo.com', 'amazon.com'] },
  { name: 'Netflix', token: 'netflix', category: 'media', domains: ['netflix.com', 'nflxext.com', 'nflximg.net', 'netflix.net', 'nflxvideo.net'] },
  { name: 'Spotify', token: 'spotify', category: 'media', domains: ['spotify.com', 'scdn.co', 'spotifycdn.com'] },
  { name: 'Disney+', token: 'disneyplus', category: 'media', domains: ['disneyplus.com', 'disney.com', 'go.com'] },
  { name: 'Hulu', token: 'hulu', category: 'media', domains: ['hulu.com'] },
  { name: 'Adobe', token: 'adobe', category: 'tech', fuzzy: false, domains: ['adobe.com', 'adobelogin.com', 'adobe.io', 'typekit.net', 'behance.net', 'adobesign.com'] },
  { name: 'Dropbox', token: 'dropbox', category: 'tech', domains: ['dropbox.com', 'dropboxusercontent.com', 'db.tt', 'dropboxapi.com'] },
  { name: 'DocuSign', token: 'docusign', category: 'tech', domains: ['docusign.com', 'docusign.net'] },
  { name: 'WeTransfer', token: 'wetransfer', category: 'tech', domains: ['wetransfer.com', 'we.tl'] },
  { name: 'Zoom', token: 'zoom', category: 'tech', fuzzy: false, domains: ['zoom.us', 'zoom.com', 'zoomgov.com'] },
  { name: 'Webex', token: 'webex', category: 'tech', domains: ['webex.com', 'cisco.com'] },
  { name: 'Cisco', token: 'cisco', category: 'tech', domains: ['cisco.com'] },
  { name: 'Slack', token: 'slack', category: 'tech', fuzzy: false, domains: ['slack.com', 'slack-edge.com'] },
  { name: 'GitHub', token: 'github', category: 'tech', domains: ['github.com', 'github.io', 'githubusercontent.com', 'githubassets.com', 'github.dev'] },
  { name: 'GitLab', token: 'gitlab', category: 'tech', domains: ['gitlab.com', 'gitlab.io'] },
  { name: 'Atlassian', token: 'atlassian', category: 'tech', domains: ['atlassian.com', 'atlassian.net', 'jira.com', 'bitbucket.org', 'trello.com'] },
  { name: 'Salesforce', token: 'salesforce', category: 'tech', domains: ['salesforce.com', 'force.com'] },
  { name: 'Oracle', token: 'oracle', category: 'tech', fuzzy: false, domains: ['oracle.com', 'oraclecloud.com'] },
  { name: 'Lenovo', token: 'lenovo', category: 'tech', domains: ['lenovo.com'] },
  { name: 'Samsung', token: 'samsung', category: 'tech', domains: ['samsung.com'] },
  { name: 'NVIDIA', token: 'nvidia', category: 'tech', domains: ['nvidia.com'] },
  { name: 'Cloudflare', token: 'cloudflare', category: 'tech', domains: ['cloudflare.com', 'cloudflare.net', 'cloudflare-dns.com', 'workers.dev', 'pages.dev', 'one.one.one.one'] },
  { name: 'GoDaddy', token: 'godaddy', category: 'tech', domains: ['godaddy.com'] },
  { name: 'Namecheap', token: 'namecheap', category: 'tech', domains: ['namecheap.com'] },
  { name: 'WordPress', token: 'wordpress', category: 'tech', domains: ['wordpress.com', 'wordpress.org', 'wp.com'] },
  { name: 'Shopify', token: 'shopify', category: 'commerce', domains: ['shopify.com', 'myshopify.com'] },
  { name: 'Squarespace', token: 'squarespace', category: 'tech', domains: ['squarespace.com'] },
  { name: 'Mailchimp', token: 'mailchimp', category: 'tech', domains: ['mailchimp.com', 'list-manage.com'] },
  { name: 'Yahoo', token: 'yahoo', category: 'tech', domains: ['yahoo.com', 'yahoo.co.jp', 'yimg.com', 'ymail.com'] },
  { name: 'Proton Mail', token: 'protonmail', category: 'tech', domains: ['proton.me', 'protonmail.com'] },
  { name: 'Zoho', token: 'zoho', category: 'tech', domains: ['zoho.com', 'zoho.in', 'zoho.eu'] },
  { name: 'OpenAI', token: 'openai', category: 'tech', domains: ['openai.com', 'chatgpt.com'] },
  { name: 'ChatGPT', token: 'chatgpt', category: 'tech', domains: ['chatgpt.com', 'openai.com'] },
  { name: 'Anthropic', token: 'anthropic', category: 'tech', domains: ['anthropic.com', 'claude.ai', 'claude.com'] },
  { name: 'Canva', token: 'canva', category: 'tech', fuzzy: false, domains: ['canva.com'] },
  { name: 'Figma', token: 'figma', category: 'tech', domains: ['figma.com'] },
  { name: 'Notion', token: 'notion', category: 'tech', fuzzy: false, domains: ['notion.so', 'notion.com'] },
  { name: 'Wikipedia', token: 'wikipedia', category: 'media', domains: ['wikipedia.org', 'wikimedia.org'] },
  { name: 'DuckDuckGo', token: 'duckduckgo', category: 'tech', domains: ['duckduckgo.com'] },
  { name: 'Okta', token: 'okta', category: 'security', domains: ['okta.com', 'oktacdn.com', 'okta-emea.com'] },

  // ---- social --------------------------------------------------------------
  { name: 'Facebook', token: 'facebook', category: 'social', domains: ['facebook.com', 'fb.com', 'fb.me', 'fbcdn.net', 'facebook.net', 'meta.com', 'messenger.com'] },
  { name: 'Instagram', token: 'instagram', category: 'social', domains: ['instagram.com', 'cdninstagram.com', 'instagr.am'] },
  { name: 'WhatsApp', token: 'whatsapp', category: 'social', domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { name: 'Messenger', token: 'messenger', category: 'social', fuzzy: false, domains: ['messenger.com', 'facebook.com'] },
  { name: 'Twitter / X', token: 'twitter', category: 'social', domains: ['twitter.com', 't.co', 'twimg.com', 'x.com'] },
  { name: 'LinkedIn', token: 'linkedin', category: 'social', domains: ['linkedin.com', 'licdn.com', 'lnkd.in'] },
  { name: 'TikTok', token: 'tiktok', category: 'social', domains: ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com'] },
  { name: 'Snapchat', token: 'snapchat', category: 'social', domains: ['snapchat.com', 'snap.com', 'sc-cdn.net'] },
  { name: 'Pinterest', token: 'pinterest', category: 'social', domains: ['pinterest.com', 'pinimg.com'] },
  { name: 'Reddit', token: 'reddit', category: 'social', domains: ['reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com'] },
  { name: 'Discord', token: 'discord', category: 'social', domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media'] },
  { name: 'Telegram', token: 'telegram', category: 'social', domains: ['telegram.org', 't.me', 'telegram.me', 'telesco.pe'] },
  { name: 'Signal', token: 'signal', category: 'social', fuzzy: false, domains: ['signal.org'] },
  { name: 'Tumblr', token: 'tumblr', category: 'social', domains: ['tumblr.com'] },
  { name: 'Twitch', token: 'twitch', category: 'social', fuzzy: false, domains: ['twitch.tv', 'jtvnw.net'] },
  { name: 'Quora', token: 'quora', category: 'social', domains: ['quora.com'] },

  // ---- gaming --------------------------------------------------------------
  { name: 'Steam', token: 'steamcommunity', category: 'gaming', domains: ['steamcommunity.com', 'steampowered.com', 'steamstatic.com'] },
  { name: 'Steam Store', token: 'steampowered', category: 'gaming', domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'] },
  { name: 'Epic Games', token: 'epicgames', category: 'gaming', domains: ['epicgames.com', 'unrealengine.com', 'fortnite.com'] },
  { name: 'Roblox', token: 'roblox', category: 'gaming', domains: ['roblox.com', 'rbxcdn.com'] },
  { name: 'PlayStation', token: 'playstation', category: 'gaming', domains: ['playstation.com', 'playstation.net', 'sonyentertainmentnetwork.com'] },
  { name: 'Xbox', token: 'xbox', category: 'gaming', domains: ['xbox.com', 'microsoft.com', 'live.com'] },
  { name: 'Nintendo', token: 'nintendo', category: 'gaming', domains: ['nintendo.com', 'nintendo.net', 'nintendo.co.jp'] },
  { name: 'Blizzard', token: 'blizzard', category: 'gaming', fuzzy: false, domains: ['blizzard.com', 'battle.net'] },
  { name: 'Riot Games', token: 'riotgames', category: 'gaming', domains: ['riotgames.com', 'leagueoflegends.com'] },
  { name: 'Minecraft', token: 'minecraft', category: 'gaming', domains: ['minecraft.net', 'mojang.com'] },

  // ---- shipping --------------------------------------------------------------
  { name: 'DHL', token: 'dhl', category: 'shipping', domains: ['dhl.com', 'dhl.de', 'dhl.co.uk', 'dhl.fr'] },
  { name: 'FedEx', token: 'fedex', category: 'shipping', domains: ['fedex.com'] },
  { name: 'UPS', token: 'ups', category: 'shipping', domains: ['ups.com'] },
  { name: 'USPS', token: 'usps', category: 'shipping', domains: ['usps.com', 'usps.gov'] },
  { name: 'Royal Mail', token: 'royalmail', category: 'shipping', domains: ['royalmail.com', 'royalmail.co.uk'] },
  { name: 'Canada Post', token: 'canadapost', category: 'shipping', domains: ['canadapost.ca', 'canadapost-postescanada.ca'] },
  { name: 'Australia Post', token: 'auspost', category: 'shipping', domains: ['auspost.com.au'] },
  { name: 'DPD', token: 'dpd', category: 'shipping', domains: ['dpd.com', 'dpd.co.uk', 'dpd.de'] },
  { name: 'Evri', token: 'evri', category: 'shipping', domains: ['evri.com'] },
  { name: 'India Post', token: 'indiapost', category: 'shipping', domains: ['indiapost.gov.in'] },
  { name: 'Blue Dart', token: 'bluedart', category: 'shipping', domains: ['bluedart.com'] },
  { name: 'Aramex', token: 'aramex', category: 'shipping', domains: ['aramex.com'] },
  { name: 'Maersk', token: 'maersk', category: 'shipping', domains: ['maersk.com'] },
  { name: 'PostNL', token: 'postnl', category: 'shipping', domains: ['postnl.nl'] },
  { name: 'La Poste', token: 'laposte', category: 'shipping', domains: ['laposte.fr', 'laposte.net'] },
  { name: 'Deutsche Post', token: 'deutschepost', category: 'shipping', domains: ['deutschepost.de'] },
  { name: 'Correos', token: 'correos', category: 'shipping', domains: ['correos.es'] },
  { name: 'Poste Italiane', token: 'posteitaliane', category: 'shipping', domains: ['poste.it', 'posteitaliane.it'] },

  // ---- commerce / travel -----------------------------------------------------
  { name: 'eBay', token: 'ebay', category: 'commerce', domains: ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.com.au', 'ebayimg.com', 'ebaystatic.com'] },
  { name: 'Walmart', token: 'walmart', category: 'commerce', domains: ['walmart.com', 'walmartimages.com'] },
  { name: 'Target', token: 'target', category: 'commerce', fuzzy: false, domains: ['target.com'] },
  { name: 'Best Buy', token: 'bestbuy', category: 'commerce', domains: ['bestbuy.com'] },
  { name: 'Costco', token: 'costco', category: 'commerce', domains: ['costco.com'] },
  { name: 'Etsy', token: 'etsy', category: 'commerce', domains: ['etsy.com', 'etsystatic.com'] },
  { name: 'AliExpress', token: 'aliexpress', category: 'commerce', domains: ['aliexpress.com', 'aliexpress.us'] },
  { name: 'Alibaba', token: 'alibaba', category: 'commerce', domains: ['alibaba.com', 'alicdn.com'] },
  { name: 'Flipkart', token: 'flipkart', category: 'commerce', domains: ['flipkart.com'] },
  { name: 'Myntra', token: 'myntra', category: 'commerce', domains: ['myntra.com'] },
  { name: 'Rakuten', token: 'rakuten', category: 'commerce', domains: ['rakuten.com', 'rakuten.co.jp'] },
  { name: 'Booking.com', token: 'booking', category: 'commerce', fuzzy: false, domains: ['booking.com', 'bstatic.com'] },
  { name: 'Airbnb', token: 'airbnb', category: 'commerce', domains: ['airbnb.com', 'airbnb.co.uk', 'muscache.com'] },
  { name: 'Expedia', token: 'expedia', category: 'commerce', domains: ['expedia.com'] },
  { name: 'Uber', token: 'uber', category: 'commerce', domains: ['uber.com'] },
  { name: 'Lyft', token: 'lyft', category: 'commerce', domains: ['lyft.com'] },
  { name: 'DoorDash', token: 'doordash', category: 'commerce', domains: ['doordash.com'] },
  { name: 'Zomato', token: 'zomato', category: 'commerce', domains: ['zomato.com'] },
  { name: 'Swiggy', token: 'swiggy', category: 'commerce', domains: ['swiggy.com'] },
  { name: 'Shein', token: 'shein', category: 'commerce', domains: ['shein.com'] },
  { name: 'Temu', token: 'temu', category: 'commerce', domains: ['temu.com'] },
  { name: 'IKEA', token: 'ikea', category: 'commerce', domains: ['ikea.com'] },
  { name: 'The Home Depot', token: 'homedepot', category: 'commerce', domains: ['homedepot.com'] },

  // ---- government ------------------------------------------------------------
  { name: 'IRS', token: 'irs', category: 'government', domains: ['irs.gov'] },
  { name: 'HMRC', token: 'hmrc', category: 'government', domains: ['gov.uk'] },
  { name: 'GOV.UK', token: 'govuk', category: 'government', domains: ['gov.uk'] },
  { name: 'Social Security Administration', token: 'ssagov', category: 'government', domains: ['ssa.gov'] },
  { name: 'USCIS', token: 'uscis', category: 'government', domains: ['uscis.gov'] },
  { name: 'Medicare', token: 'medicare', category: 'government', domains: ['medicare.gov'] },
  { name: 'DVLA', token: 'dvla', category: 'government', domains: ['gov.uk'] },
  { name: 'Income Tax Department (India)', token: 'incometax', category: 'government', domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
  { name: 'UIDAI (Aadhaar)', token: 'uidai', category: 'government', domains: ['uidai.gov.in'] },
  { name: 'Aadhaar', token: 'aadhaar', category: 'government', domains: ['uidai.gov.in'] },

  // ---- telecom ----------------------------------------------------------------
  { name: 'AT&T', token: 'att', category: 'telecom', domains: ['att.com', 'att.net'] },
  { name: 'Verizon', token: 'verizon', category: 'telecom', domains: ['verizon.com', 'verizonwireless.com', 'vzw.com'] },
  { name: 'T-Mobile', token: 'tmobile', category: 'telecom', domains: ['t-mobile.com', 'tmobile.com'] },
  { name: 'Vodafone', token: 'vodafone', category: 'telecom', domains: ['vodafone.com', 'vodafone.co.uk', 'vodafone.de'] },
  { name: 'Orange', token: 'orange', category: 'telecom', fuzzy: false, domains: ['orange.fr', 'orange.com'] },
  { name: 'Airtel', token: 'airtel', category: 'telecom', domains: ['airtel.in', 'airtel.com'] },
  { name: 'Jio', token: 'jio', category: 'telecom', domains: ['jio.com'] },
  { name: 'Xfinity', token: 'xfinity', category: 'telecom', domains: ['xfinity.com', 'comcast.net', 'comcast.com'] },
  { name: 'Spectrum', token: 'spectrum', category: 'telecom', fuzzy: false, domains: ['spectrum.com', 'spectrum.net'] },
  { name: 'Optus', token: 'optus', category: 'telecom', domains: ['optus.com.au'] },
  { name: 'Telstra', token: 'telstra', category: 'telecom', domains: ['telstra.com.au', 'telstra.com'] },

  // ---- security ---------------------------------------------------------------
  { name: 'Norton', token: 'norton', category: 'security', fuzzy: false, domains: ['norton.com', 'nortonlifelock.com'] },
  { name: 'McAfee', token: 'mcafee', category: 'security', domains: ['mcafee.com'] },
  { name: 'Avast', token: 'avast', category: 'security', domains: ['avast.com'] },
  { name: 'Kaspersky', token: 'kaspersky', category: 'security', domains: ['kaspersky.com'] },
  { name: 'Bitdefender', token: 'bitdefender', category: 'security', domains: ['bitdefender.com'] },
  { name: 'Malwarebytes', token: 'malwarebytes', category: 'security', domains: ['malwarebytes.com'] },
  { name: 'LastPass', token: 'lastpass', category: 'security', domains: ['lastpass.com'] },
  { name: '1Password', token: '1password', category: 'security', domains: ['1password.com'] },
  { name: 'Bitwarden', token: 'bitwarden', category: 'security', domains: ['bitwarden.com'] },
];

/**
 * Hyphen-separated words that, next to a brand token, turn a brand mention
 * into an impersonation pattern ("paypal-login", "apple-security-verify").
 */
export const SUSPICIOUS_KEYWORDS: ReadonlySet<string> = new Set([
  'login', 'logon', 'signin', 'sign', 'verify', 'verification', 'verified', 'secure', 'security', 'account',
  'accounts', 'update', 'updates', 'confirm', 'confirmation', 'support', 'helpdesk', 'service', 'services',
  'billing', 'payment', 'payments', 'pay', 'wallet', 'recover', 'recovery', 'unlock', 'unlocked', 'auth',
  'authenticate', 'authentication', 'alert', 'alerts', 'notice', 'validate', 'validation', 'reset', 'password',
  'webscr', 'customer', 'refund', 'refunds', 'invoice', 'delivery', 'parcel', 'package', 'tracking', 'shipment',
  'customs', 'redelivery', 'reschedule', 'gift', 'giftcard', 'prize', 'reward', 'rewards', 'bonus', 'claim',
  'airdrop', 'nitro', 'free', 'promo', 'suspended', 'locked', 'limited', 'restore', 'resolution', 'online',
  'portal', 'id', 'sso', 'mfa', '2fa', 'kyc', 'tax', 'taxrefund',
]);

/** TLDs with a high abuse rate (§31.2 "Suspicious TLD — Low"). */
export const SUSPICIOUS_TLDS: ReadonlySet<string> = new Set([
  'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'work', 'support', 'country',
  'kim', 'loan', 'men', 'buzz', 'rest', 'fit', 'cam', 'icu', 'cyou', 'sbs', 'monster', 'quest', 'bar', 'cfd',
  'lol', 'online', 'site', 'live', 'shop', 'store', 'best', 'review', 'party', 'trade', 'date', 'win', 'bid',
]);

// Technical categories (Talkback-style short badges) and product/technology topics (#hashtags).
// Keyword-based: a story can have several categories; topics are specific products.

export const CATEGORIES = [
  // [code, label, regex on headline + summary]
  ['app', 'Application Security', /\b(web ?app|XSS|cross-site|SQL injection|SQLi|SSRF|CSRF|deserializ|path traversal|directory traversal|auth(entication)? bypass|IDOR|API (security|flaw|vulnerab)|prototype pollution|template injection|SSTI|file upload|open redirect|WAF|OAuth|JWT)\b/i],
  ['exp', 'Exploit Development', /\b(exploit(s|ed|ation)?|proof[- ]of[- ]concept|PoC|RCE|remote code execution|memory corruption|heap (overflow|spray)|buffer overflow|use[- ]after[- ]free|UAF|out-of-bounds|type confusion|race condition|fuzz(ing|er)|zero[- ]?day|0-?day|sandbox escape|privilege escalation|LPE)\b/i],
  ['net', 'Network Security', /\b(network|router|firewall|VPN|DNS|BGP|TLS|SSL|DDoS|botnet|proxy|edge device|gateway|Wi-?Fi|Bluetooth|SMB|RDP|SSH|packet|IPv6|traffic)\b/i],
  ['mal', 'Malware', /\b(malware|ransomware|trojan|infostealer|stealer|backdoor|RAT|loader|botnet|wiper|rootkit|spyware|worm|dropper|implant|C2|command[- ]and[- ]control)\b/i],
  ['rev', 'Reverse Engineering', /\b(reverse[- ]engineer|reversing|decompil|disassembl|Ghidra|IDA Pro|Binary Ninja|unpack(ing|ed)|deobfuscat|firmware analysis|dissect|teardown|under the hood|deep dive)\b/i],
  ['cloud', 'Cloud Security', /\b(cloud|AWS|Azure|GCP|Google Cloud|Kubernetes|K8s|container|Docker|serverless|S3 bucket|IAM|Entra|tenant|SaaS|Snowflake|Salesforce)\b/i],
  ['crypto', 'Cryptography', /\b(cryptograph|encryption|decrypt|cipher|post-quantum|quantum-safe|PQC|TLS certificate|certificate authority|PKI|key exchange|signature|hash function|RSA|AES|elliptic)\b/i],
  ['id', 'Identity & Access', /\b(identity|Active Directory|AD CS|Kerberos|NTLM|LDAP|SSO|SAML|MFA|2FA|multi-factor|passkey|password|credential|Okta|Entra ID|session token|account takeover|OAuth)\b/i],
  ['os', 'Operating Systems', /\b(Windows|Linux|kernel|macOS|iOS|Android|driver|BYOVD|UEFI|bootkit|hypervisor|ESXi|Hyper-V|privilege escalation)\b/i],
  ['mobile', 'Mobile', /\b(Android|iOS|iPhone|iPad|mobile|smartphone|APK|Google Play|App Store|SMS|Pegasus|spyware)\b/i],
  ['ics', 'ICS / OT', /\b(ICS|SCADA|OT\b|operational technology|PLC|industrial|Siemens|Schneider|Rockwell|Modbus|utility|utilities|power grid|water (utility|system|treatment)|manufacturing plant)\b/i],
  ['dfir', 'Forensics & IR', /\b(forensic|incident response|DFIR|threat hunt|detection engineering|Sigma|YARA|EDR|SIEM|log analysis|memory analysis|triage|IOCs?|indicators of compromise|timeline)\b/i],
  ['social', 'Social Engineering', /\b(phish|smish|vish|social engineering|scam|fraud|BEC|business email compromise|deepfake|impersonat|lure|ClickFix|fake (CAPTCHA|update|job))\b/i],
  ['supply', 'Supply Chain', /\b(supply[- ]chain|npm|PyPI|RubyGems|crates\.io|NuGet|malicious package|dependency|open[- ]source package|GitHub Actions?|CI\/CD|VS ?Code extension|typosquat)\b/i],
  ['ai', 'AI Security', /\b(AI|LLM|ChatGPT|Copilot|Gemini|Claude|prompt injection|jailbreak|agentic|MCP|machine learning|deepfakes?|AI agents?|AI models?)\b/],
  ['privacy', 'Privacy & Policy', /\b(privacy|surveillance|tracking|GDPR|data protection|regulat|legislation|law enforcement|FBI|Europol|sanction|indict|arrest|court|lawsuit|fine[ds]?|policy)\b/i],
  ['hw', 'Hardware', /\b(CPU|processor|side[- ]channel|Spectre|Rowhammer|chip|TPM|firmware|BMC|IPMI|hardware|FPGA|GPU)\b/i],
];

// Products & technologies → #topics. [name, kind, regex]
export const PRODUCTS = [
  ['Windows', 'Operating system', /\bWindows\b(?! Server Update)/], ['Windows Server', 'Operating system', /\bWindows Server\b/],
  ['macOS', 'Operating system', /\bmacOS\b/i], ['iOS', 'Mobile OS', /\biOS\b|\biPadOS\b/], ['Android', 'Mobile OS', /\bAndroid\b/],
  ['Linux kernel', 'Operating system', /\bLinux kernel\b|\bkernel\b.{0,20}\bLinux\b/i], ['ChromeOS', 'Operating system', /\bChromeOS\b/i],
  ['Chrome', 'Browser', /\bChrome\b(?!OS)|\bChromium\b/], ['Firefox', 'Browser', /\bFirefox\b/], ['Safari', 'Browser', /\bSafari\b|\bWebKit\b/], ['Edge', 'Browser', /\bMicrosoft Edge\b/],
  ['Exchange', 'Mail server', /\bExchange Server\b|\bExchange Online\b|\bMicrosoft Exchange\b/], ['SharePoint', 'Collaboration', /\bSharePoint\b/], ['Outlook', 'Mail client', /\bOutlook\b/],
  ['Microsoft 365', 'SaaS suite', /\b(Microsoft|Office) 365\b|\bM365\b/], ['Teams', 'Collaboration', /\bMicrosoft Teams\b/], ['Entra ID', 'Identity', /\bEntra( ID)?\b|\bAzure AD\b/],
  ['Active Directory', 'Identity', /\bActive Directory\b|\bAD CS\b|\bADCS\b/], ['Kerberos', 'Protocol', /\bKerberos\b/], ['NTLM', 'Protocol', /\bNTLM\b/],
  ['Azure', 'Cloud', /\bAzure\b/], ['AWS', 'Cloud', /\bAWS\b|\bAmazon Web Services\b/], ['Google Cloud', 'Cloud', /\bGoogle Cloud\b|\bGCP\b/],
  ['Kubernetes', 'Container orchestration', /\bKubernetes\b|\bK8s\b/i], ['Docker', 'Containers', /\bDocker\b/], ['containerd', 'Containers', /\bcontainerd\b|\brunc\b/],
  ['NetScaler', 'ADC / VPN gateway', /\bNetScaler\b|\bCitrix (ADC|Gateway)\b/i], ['FortiGate', 'Firewall / VPN', /\bFortiGate\b|\bFortiOS\b|\bFortiProxy\b/i], ['FortiWeb', 'WAF', /\bFortiWeb\b/i], ['FortiManager', 'Management', /\bFortiManager\b/i],
  ['PAN-OS', 'Firewall', /\bPAN-OS\b|\bGlobalProtect\b/i], ['Ivanti Connect Secure', 'VPN', /\bConnect Secure\b|\bPulse Secure\b|\bPolicy Secure\b/i], ['Ivanti EPMM', 'Mobile management', /\bEPMM\b|\bMobileIron\b/i],
  ['Cisco ASA', 'Firewall', /\bCisco ASA\b|\bFirepower\b|\bFTD\b|\bAdaptive Security Appliance\b/], ['Cisco IOS XE', 'Network OS', /\bIOS XE\b/], ['Cisco ISE', 'NAC', /\bIdentity Services Engine\b|\bCisco ISE\b/],
  ['SonicOS', 'VPN / Firewall', /\bSonicOS\b|\bSMA ?\d{3,4}\b/i], ['Juniper Junos', 'Network OS', /\bJunos\b/i], ['F5 BIG-IP', 'ADC', /\bBIG-IP\b/i], ['Check Point Gateway', 'Firewall', /\bCheck Point (Quantum|Security Gateway|VPN)\b/i],
  ['Zyxel', 'Network devices', /\bZyxel\b/i], ['MikroTik RouterOS', 'Router OS', /\bMikroTik\b|\bRouterOS\b/i], ['TP-Link', 'Routers', /\bTP-Link\b/i], ['D-Link', 'Routers', /\bD-Link\b/i], ['Ubiquiti', 'Network devices', /\bUbiquiti\b|\bUniFi\b/i],
  ['VMware ESXi', 'Hypervisor', /\bESXi\b/i], ['VMware vCenter', 'Virtualization', /\bvCenter\b/i], ['Hyper-V', 'Hypervisor', /\bHyper-V\b/i], ['Proxmox', 'Hypervisor', /\bProxmox\b/i],
  ['Veeam', 'Backup', /\bVeeam\b/i], ['Commvault', 'Backup', /\bCommvault\b/i], ['Oracle E-Business Suite', 'ERP', /\bE-Business Suite\b|\bOracle EBS\b/i], ['Oracle WebLogic', 'App server', /\bWebLogic\b/i], ['Oracle PeopleSoft', 'HR / ERP', /\bPeopleSoft\b/i],
  ['SAP NetWeaver', 'ERP platform', /\bNetWeaver\b|\bSAP\b/], ['Salesforce', 'CRM', /\bSalesforce\b/i], ['Snowflake', 'Data cloud', /\bSnowflake\b/i], ['ServiceNow', 'ITSM', /\bServiceNow\b/i], ['Workday', 'HR SaaS', /\bWorkday\b/],
  ['Confluence', 'Wiki', /\bConfluence\b/i], ['Jira', 'Issue tracker', /\bJira\b/i], ['GitLab', 'DevOps', /\bGitLab\b/i], ['GitHub', 'DevOps', /\bGitHub\b/], ['GitHub Actions', 'CI/CD', /\bGitHub Actions?\b/i], ['Jenkins', 'CI/CD', /\bJenkins\b/i], ['TeamCity', 'CI/CD', /\bTeamCity\b/i], ['JFrog Artifactory', 'Artifact repo', /\bArtifactory\b|\bJFrog\b/i],
  ['npm', 'Package registry', /\bnpm\b/], ['PyPI', 'Package registry', /\bPyPI\b/], ['VS Code', 'Code editor', /\bVS ?Code\b|\bVisual Studio Code\b|\bOpen VSX\b/i], ['Chrome extensions', 'Browser extensions', /\b(Chrome|browser) extensions?\b/i],
  ['WordPress', 'CMS', /\bWordPress\b|\bWooCommerce\b/i], ['Drupal', 'CMS', /\bDrupal\b/i], ['Magento', 'E-commerce', /\bMagento\b|\bAdobe Commerce\b/i], ['Apache Tomcat', 'App server', /\bTomcat\b/i], ['Apache Struts', 'Framework', /\bStruts\b/i], ['Log4j', 'Library', /\bLog4j\b|\bLog4Shell\b/i], ['ActiveMQ', 'Message broker', /\bActiveMQ\b/i],
  ['Nginx', 'Web server', /\bnginx\b/i], ['OpenSSH', 'Remote access', /\bOpenSSH\b/i], ['OpenSSL', 'Crypto library', /\bOpenSSL\b/i], ['glibc', 'Library', /\bglibc\b/i], ['sudo', 'Utility', /\bsudo\b/], ['XZ Utils', 'Library', /\bXZ Utils\b|\bliblzma\b/i],
  ['MOVEit', 'File transfer', /\bMOVEit\b/i], ['CrushFTP', 'File transfer', /\bCrushFTP\b/i], ['Cleo', 'File transfer', /\bCleo (Harmony|VLTrader|LexiCom)\b/i], ['GoAnywhere', 'File transfer', /\bGoAnywhere\b/i], ['Kiteworks', 'File transfer', /\bKiteworks\b/i],
  ['ScreenConnect', 'Remote access', /\bScreenConnect\b/i], ['AnyDesk', 'Remote access', /\bAnyDesk\b/i], ['TeamViewer', 'Remote access', /\bTeamViewer\b/i], ['SimpleHelp', 'Remote access', /\bSimpleHelp\b/i], ['Kaseya VSA', 'RMM', /\bKaseya\b/i], ['N-able', 'RMM', /\bN-able\b|\bN-central\b/i],
  ['SolarWinds', 'IT management', /\bSolarWinds\b/i], ['Zimbra', 'Mail server', /\bZimbra\b/i], ['Roundcube', 'Webmail', /\bRoundcube\b/i], ['Microsoft SQL Server', 'Database', /\bSQL Server\b/i], ['MongoDB', 'Database', /\bMongoDB\b/i], ['Redis', 'Database', /\bRedis\b/i], ['Elasticsearch', 'Database', /\bElasticsearch\b/i],
  ['Okta', 'Identity', /\bOkta\b/], ['Cloudflare', 'CDN / security', /\bCloudflare\b/i], ['CrowdStrike Falcon', 'EDR', /\bCrowdStrike\b/i], ['Microsoft Defender', 'EDR', /\bDefender\b/], ['Signal', 'Messaging', /\bSignal\b(?= (app|messenger|messages|chats?|users))/i], ['WhatsApp', 'Messaging', /\bWhatsApp\b/i], ['Telegram', 'Messaging', /\bTelegram\b/i],
  ['ChatGPT', 'AI assistant', /\bChatGPT\b/i], ['Copilot', 'AI assistant', /\bCopilot\b/i], ['Claude', 'AI assistant', /\bClaude\b/], ['Gemini', 'AI assistant', /\bGemini\b/], ['MCP', 'AI protocol', /\bMCP\b|\bModel Context Protocol\b/], ['OpenClaw', 'AI agent', /\bOpenClaw\b/i], ['vLLM', 'LLM inference', /\bvLLM\b/],
  ['iPhone', 'Mobile device', /\biPhone\b/i], ['Pixel', 'Mobile device', /\bPixel\b(?= \d| phones?)/], ['Galaxy', 'Mobile device', /\bGalaxy (S|Z|A|Tab)\b/], ['Snapdragon', 'Chipset', /\bSnapdragon\b/i],
  ['UEFI', 'Firmware', /\bUEFI\b|\bSecure Boot\b/i], ['SIMATIC', 'ICS', /\bSIMATIC\b/], ['Modicon', 'ICS', /\bModicon\b/i], ['Allen-Bradley', 'ICS', /\bAllen-Bradley\b|\bControlLogix\b/i],
  ['Crypto exchanges', 'Crypto', /\bcrypto(currency)? exchange\b|\bBitcoin\b|\bEthereum\b|\bDeFi\b|\bwallet drainer\b/i], ['Starlink', 'Satellite', /\bStarlink\b/i], ['Tor', 'Anonymity network', /\bTor (network|browser)\b|\.onion\b/i],
];

export const catRegex = CATEGORIES.map(([code, , re]) => [code, re]);

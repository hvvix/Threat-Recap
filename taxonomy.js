// Keyword rules used to tag stories. Everything here is a heuristic on the
// headline + summary, so tags are "likely", never authoritative.

export const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

export const TAG_RULES = {
  vuln: /vulnerab|\bflaws?\b|\bpatch(es|ed)?\b|security update|\bRCE\b|remote code execution|privilege escalation|\bbugs?\b|out-of-band|hotfix|security bulletin|advisory/i,
  zeroday: /zero[- ]?days?|\b0[- ]?days?\b|actively exploited|exploited in the wild|in[- ]the[- ]wild|under active exploitation|active exploitation|exploited as a zero|mass[- ]exploit|exploitation attempts/i,
  breach: /\bbreach|data leak|\bleak(ed|s)?\b|stolen data|data theft|exposed (data|records|database|personal)|hackers? stole|stole .{0,40}data|compromised (data|accounts|records)|personal (data|information) of|customer data|records exposed|data of [\d.,]+ ?(million|people|customers|users)|cyberattack on|cyber ?attack at|hit by (a )?(cyber|ransomware)|confirms (cyber|security) incident|security incident/i,
  apt: /\bAPT\b|\bAPT ?\d+|nation[- ]state|state[- ]sponsored|state[- ]backed|espionage|\bspy(ing)? campaign|government[- ]backed|\bUNC\d{3,5}\b|\bStorm-\d{4}\b|\bTA\d{3,4}\b|(Chinese|Russian|Iranian|North Korean|DPRK|PRC)[- ](linked|backed|nexus|hackers|state|APT|threat|actors?|group)/i,
  ransomware: /ransomware|\bransom\b|extortion (gang|group)|data extortion|double extortion|LockBit|Akira|Qilin|BlackCat|ALPHV|Play ransomware|Black Basta|Medusa|RansomHub|Cl0p|Clop\b|INC Ransom|SafePay|DragonForce|Interlock|Rhysida|BianLian|8Base|Hunters International|Scattered Spider|ShinyHunters|Warlock/i,
  malware: /malware|trojan|infostealer|\bstealer\b|botnet|backdoor|\bRAT\b|\bloader\b|\bwiper\b|rootkit|spyware|keylogger|\bworm\b|dropper|implant|cryptominer/i,
  supply: /supply[- ]chain|\bnpm\b|\bPyPI\b|malicious (packages?|extensions?|libraries|crates?)|RubyGems|crates\.io|\bNuGet\b|VS ?Code extension|Open VSX|browser extension|GitHub Actions?|open[- ]source (package|library|project)s?|typosquat|dependency confusion|Docker Hub/i,
  phishing: /phish|smishing|vishing|\bBEC\b|business email compromise|credential harvest|fake login|social engineering/i,
  ai: /\bAI\b|\bLLMs?\b|ChatGPT|Gemini|Copilot|\bClaude\b|agentic|prompt injection|\bMCP\b|deepfake|machine learning|\bGenAI\b/i,
  law: /regulat|legislation|\bbill\b|\bSEC\b|sanction|indict|arrest|charged|sentenced|pleads? guilty|extradit|law enforcement|Europol|\bFBI\b|\bDOJ\b|takedown|seized|court|lawsuit|fine[ds]?\b|policy|executive order/i,
};

// Tab membership is derived from tags (see app.js); labels live here for build-time uses (digest).
export const TAG_LABELS = {
  vuln: 'Vulnerability', zeroday: 'Zero-day', breach: 'Breach', apt: 'APT', ransomware: 'Ransomware',
  malware: 'Malware', supply: 'Supply chain', phishing: 'Phishing', ai: 'AI', law: 'Law & policy',
  research: 'Research', advisory: 'Advisory',
};

// Threat actors (aliases, origin, MITRE IDs) and malware families live in actors.js.
export { ACTORS, ACTOR_INFO, MALWARE_RE, slug } from './actors.js';

// Generic identifiers that are worth surfacing even without an alias entry.
export const ACTOR_PATTERNS = [/\bAPT ?\d{1,3}\b/g, /\bUNC\d{3,5}\b/g, /\bStorm-\d{4}\b/g, /\bTA\d{3,4}\b/g, /\bUAC-\d{4}\b/g];

export const VENDORS = [
  ['Microsoft', /Microsoft|Windows|Exchange Server|SharePoint|Azure|\bEntra\b|Microsoft Outlook|Outlook (email|client|zero-click)|Office 365|Microsoft 365|Hyper-V|\.NET\b|Microsoft Teams|\bIntune\b/i],
  ['Google', /Google|Chrome\b|Chromium|Android|Pixel\b|Gmail|\bGCP\b|Google Workspace/i],
  ['Apple', /Apple|\biOS\b|iPadOS|macOS|Safari|WebKit|iPhone|watchOS|visionOS/i],
  ['Cisco', /Cisco|\bIOS XE\b|\bASA\b|Firepower|Webex|Meraki|Talos/i],
  ['Fortinet', /Fortinet|FortiGate|FortiOS|FortiWeb|FortiManager|FortiClient|FortiSIEM|FortiProxy|FortiVoice|FortiSwitch/i],
  ['Palo Alto Networks', /Palo Alto Networks|PAN-OS|GlobalProtect|Cortex XDR|Prisma/i],
  ['Ivanti', /Ivanti|Connect Secure|Policy Secure|\bEPMM\b|MobileIron|Pulse Secure/i],
  ['Citrix', /Citrix|NetScaler/i],
  ['VMware / Broadcom', /VMware|vCenter|ESXi|Workstation Pro|vSphere|Aria\b|Broadcom/i],
  ['Oracle', /Oracle|WebLogic|E-Business Suite|\bJava SE\b|MySQL/i],
  ['SAP', /\bSAP\b|NetWeaver/i],
  ['Atlassian', /Atlassian|Confluence|Jira|Bitbucket/i],
  ['Juniper', /Juniper|Junos/i],
  ['SonicWall', /SonicWall|SonicOS|\bSMA ?\d{3,4}\b/i],
  ['F5', /\bF5\b|BIG-IP/i],
  ['Adobe', /Adobe|Acrobat|ColdFusion|Magento|Experience Manager/i],
  ['Linux', /\bLinux\b|Linux kernel|glibc|\bsudo\b|OpenSSH|systemd/i],
  ['AWS', /\bAWS\b|Amazon Web Services|\bS3\b buckets?|Amazon/i],
  ['Okta', /\bOkta\b/i],
  ['Salesforce', /Salesforce|Salesloft|Salesloft Drift/i],
  ['GitHub / GitLab', /GitHub|GitLab/i],
  ['WordPress', /WordPress|WooCommerce/i],
  ['Zyxel', /Zyxel/i],
  ['Veeam', /Veeam/i],
  ['Progress', /Progress Software|MOVEit|WS_FTP|Telerik|Kemp\b/i],
  ['CrushFTP', /CrushFTP/i],
  ['Cleo', /\bCleo\b/i],
  ['Commvault', /Commvault/i],
  ['SolarWinds', /SolarWinds/i],
  ['ConnectWise', /ConnectWise|ScreenConnect/i],
  ['Check Point', /Check Point (Quantum|Security Gateway|VPN)|Check Point firewall/i],
  ['Samsung', /Samsung/i],
  ['Qualcomm', /Qualcomm|Snapdragon/i],
  ['Mozilla', /Mozilla|Firefox|Thunderbird/i],
  ['OpenAI', /OpenAI|ChatGPT/i],
  ['Anthropic', /Anthropic|\bClaude\b/i],
  ['Siemens', /Siemens/i],
  ['Schneider Electric', /Schneider Electric/i],
  ['Rockwell', /Rockwell Automation/i],
  ['Docker / Kubernetes', /Docker|Kubernetes|\bk8s\b|containerd|runc\b/i],
  ['Apache', /\bApache\b|Tomcat|Struts|Log4j|ActiveMQ|OFBiz/i],
  ['Zimbra', /Zimbra/i],
  ['Roundcube', /Roundcube/i],
  ['Sophos', /Sophos (Firewall|XG)/i],
  ['TP-Link / D-Link / routers', /TP-Link|D-Link|Netgear|ASUS router|DrayTek|Tenda|Ubiquiti|MikroTik/i],
  ['Trend Micro', /Trend Micro Apex|Apex One/i],
];

// ATT&CK technique guesses. [id, name, regex]
export const ATTACK = [
  ['T1190', 'Exploit Public-Facing Application', /exploit(ed|ing|ation)? .{0,40}(VPN|firewall|gateway|server|appliance|edge device|web app|public-facing)|(VPN|firewall|appliance|edge device)s? .{0,30}exploit/i],
  ['T1566', 'Phishing', /phish|spear-?phish|malicious (email|attachment)|lure document/i],
  ['T1486', 'Data Encrypted for Impact', /ransomware|encrypt(ed|s|ing) (files|data|systems|servers)/i],
  ['T1567', 'Exfiltration Over Web Service', /exfiltrat/i],
  ['T1078', 'Valid Accounts', /stolen credentials|valid accounts|compromised credentials|credential stuffing|password spray/i],
  ['T1110', 'Brute Force', /brute[- ]forc|password spray|credential stuffing/i],
  ['T1195', 'Supply Chain Compromise', /supply[- ]chain (attack|compromise)|malicious (npm|PyPI|package|update)|trojanized|typosquat/i],
  ['T1189', 'Drive-by Compromise', /drive-by|watering[- ]hole|malvertising|fake (browser )?update|ClickFix|FakeUpdates|SocGholish/i],
  ['T1204', 'User Execution', /ClickFix|fake CAPTCHA|tricks? (users|victims) into (running|executing|pasting)/i],
  ['T1059', 'Command and Scripting Interpreter', /PowerShell|malicious scripts?|\bVBScript\b|JavaScript loader|bash script|Python script/i],
  ['T1055', 'Process Injection', /process injection|DLL injection|process hollowing|shellcode injection/i],
  ['T1574', 'Hijack Execution Flow', /DLL side-?loading|DLL hijack|search order hijack/i],
  ['T1547', 'Boot or Logon Autostart', /persistence via (registry|run key|startup)|autostart|run keys?/i],
  ['T1053', 'Scheduled Task/Job', /scheduled tasks?|cron ?jobs?/i],
  ['T1505.003', 'Web Shell', /web ?shells?/i],
  ['T1021', 'Remote Services', /lateral movement|\bRDP\b|remote desktop|\bSMB\b|WinRM/i],
  ['T1219', 'Remote Access Software', /remote (monitoring and management|access) (tool|software)|\bRMM\b|AnyDesk|ScreenConnect|TeamViewer/i],
  ['T1003', 'OS Credential Dumping', /credential dump|LSASS|Mimikatz|NTDS\.dit|SAM hive/i],
  ['T1555', 'Credentials from Password Stores', /infostealer|stealer malware|browser credentials|password stores?|steals? (saved )?passwords/i],
  ['T1539', 'Steal Web Session Cookie', /session (cookies?|tokens?) (theft|hijack|stolen)|cookie theft|steal(s|ing)? (session )?cookies/i],
  ['T1621', 'MFA Request Generation', /MFA (fatigue|bombing|push spam)|push bombing/i],
  ['T1111', 'MFA Interception', /MFA bypass|bypass(es|ing)? (MFA|multi-factor|2FA)|adversary-in-the-middle|\bAiTM\b/i],
  ['T1068', 'Exploitation for Privilege Escalation', /privilege escalation|\bLPE\b|elevation of privilege|\bEoP\b/i],
  ['T1211', 'Exploitation for Defense Evasion', /\bBYOVD\b|bring your own vulnerable driver|vulnerable driver/i],
  ['T1562', 'Impair Defenses', /disable(s|d)? (antivirus|EDR|security tools|Defender)|EDR killer|kill(s)? EDR|AV killer/i],
  ['T1027', 'Obfuscated Files or Information', /obfuscat|packed payload|steganograph/i],
  ['T1071', 'Application Layer Protocol (C2)', /command[- ]and[- ]control|\bC2\b|\bC&C\b/i],
  ['T1090', 'Proxy', /residential proxy|proxy botnet|\bORB\b network|operational relay box/i],
  ['T1498', 'Network Denial of Service', /\bDDoS\b|denial[- ]of[- ]service/i],
  ['T1485', 'Data Destruction', /\bwiper\b|data destruction|destructive malware/i],
  ['T1657', 'Financial Theft', /crypto(currency)? (theft|heist)|stole .{0,20}(crypto|\$\d)|\bBEC\b|business email compromise|wire fraud/i],
  ['T1098', 'Account Manipulation', /OAuth (app|token|consent)|consent phishing|illicit consent/i],
  ['T1133', 'External Remote Services', /\bVPN\b (credentials|access|account)|exposed RDP|Citrix Gateway access/i],
  ['T1210', 'Exploitation of Remote Services', /wormable|remote services exploit/i],
  ['T1601', 'Modify System Image', /firmware (implant|backdoor)|bootkit|UEFI (implant|malware|bootkit)/i],
];

// Promotional posts (webinars, virtual events, sponsored) are dropped from every feed.
export const NOISE = /^\s*\[(virtual event|webinar|sponsored|event|podcast|ad)\]|^\s*(webinar|sponsored|register now|upcoming webinar)\s*[:|–-]|\bsponsored (post|content)\b|^\s*\[?(on-demand|live) webinar/i;

// Relevance filter for general-news feeds marked "filter": true.
export const RELEVANCE = /secur|hack|breach|vulnerab|malware|ransom|cyber|exploit|\bspy|spyware|surveil|privacy|leak|phish|scam|CVE-|attack|stalkerware|\bFBI\b|\bNSA\b|\bCISA\b|encrypt|password|zero-day|backdoor|botnet|fraud|extortion|dark ?web|infosec/i;

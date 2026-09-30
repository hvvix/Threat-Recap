// Threat actors and malware families: canonical name, aliases, origin, MITRE ATT&CK group ID.
// Aliases are matched case-insensitively on word boundaries. MITRE IDs are only given
// where the mapping is well established; the actor pages link to a MITRE search otherwise.

export const ACTOR_INFO = [
  { name: 'APT28', origin: 'Russia (GRU)', mitre: 'G0007', aliases: ['APT28', 'APT 28', 'Fancy Bear', 'Forest Blizzard', 'Sofacy', 'Sednit', 'STRONTIUM', 'UAC-0001', 'BlueDelta', 'Pawn Storm'] },
  { name: 'APT29', origin: 'Russia (SVR)', mitre: 'G0016', aliases: ['APT29', 'APT 29', 'Cozy Bear', 'Midnight Blizzard', 'NOBELIUM', 'Cloaked Ursa', 'UNC2452', 'The Dukes'] },
  { name: 'Sandworm', origin: 'Russia (GRU)', mitre: 'G0034', aliases: ['Sandworm', 'Seashell Blizzard', 'APT44', 'APT 44', 'Voodoo Bear', 'UAC-0133', 'IRIDIUM'] },
  { name: 'Turla', origin: 'Russia (FSB)', mitre: 'G0010', aliases: ['Turla', 'Secret Blizzard', 'Venomous Bear', 'Snake malware', 'Waterbug'] },
  { name: 'Gamaredon', origin: 'Russia (FSB)', mitre: 'G0047', aliases: ['Gamaredon', 'Primitive Bear', 'Aqua Blizzard', 'UAC-0010', 'Shuckworm'] },
  { name: 'Star Blizzard', origin: 'Russia (FSB)', aliases: ['Star Blizzard', 'Callisto Group', 'ColdRiver', 'Cold River', 'SEABORGIUM'] },
  { name: 'Cadet Blizzard', origin: 'Russia (GRU)', aliases: ['Cadet Blizzard', 'Ember Bear', 'UAC-0056', 'DEV-0586'] },
  { name: 'Void Blizzard', origin: 'Russia', aliases: ['Void Blizzard', 'Laundry Bear'] },
  { name: 'Lazarus Group', origin: 'North Korea', mitre: 'G0032', aliases: ['Lazarus', 'Hidden Cobra', 'Diamond Sleet', 'ZINC', 'TraderTraitor', 'Jade Sleet', 'BlueNoroff', 'Sapphire Sleet', 'AppleJeus', 'Famous Chollima', 'Contagious Interview', 'Labyrinth Chollima'] },
  { name: 'Kimsuky', origin: 'North Korea', mitre: 'G0094', aliases: ['Kimsuky', 'Emerald Sleet', 'Velvet Chollima', 'APT43', 'APT 43', 'Black Banshee', 'Thallium'] },
  { name: 'APT37', origin: 'North Korea', mitre: 'G0067', aliases: ['APT37', 'APT 37', 'ScarCruft', 'Reaper group', 'Ruby Sleet', 'InkySquid'] },
  { name: 'Andariel', origin: 'North Korea', mitre: 'G0138', aliases: ['Andariel', 'Onyx Sleet', 'APT45', 'APT 45', 'Silent Chollima'] },
  { name: 'DPRK IT workers', origin: 'North Korea', aliases: ['North Korean IT worker', 'North Korean IT workers', 'DPRK IT worker', 'DPRK IT workers', 'remote IT worker scheme', 'laptop farm', 'laptop farms'] },
  { name: 'APT41', origin: 'China', mitre: 'G0096', aliases: ['APT41', 'APT 41', 'Wicked Panda', 'Brass Typhoon', 'Barium', 'Winnti', 'Double Dragon'] },
  { name: 'Volt Typhoon', origin: 'China', mitre: 'G1017', aliases: ['Volt Typhoon', 'Vanguard Panda', 'BRONZE SILHOUETTE', 'Insidious Taurus'] },
  { name: 'Salt Typhoon', origin: 'China', aliases: ['Salt Typhoon', 'GhostEmperor', 'FamousSparrow', 'Earth Estries', 'UNC2286'] },
  { name: 'Silk Typhoon', origin: 'China', mitre: 'G0125', aliases: ['Silk Typhoon', 'HAFNIUM'] },
  { name: 'Flax Typhoon', origin: 'China', aliases: ['Flax Typhoon', 'Ethereal Panda', 'Integrity Technology Group'] },
  { name: 'Linen Typhoon', origin: 'China', mitre: 'G0027', aliases: ['Linen Typhoon', 'APT27', 'APT 27', 'Emissary Panda', 'LuckyMouse', 'Iron Tiger'] },
  { name: 'Mustang Panda', origin: 'China', mitre: 'G0129', aliases: ['Mustang Panda', 'Twill Typhoon', 'Earth Preta', 'RedDelta', 'Stately Taurus', 'TA416'] },
  { name: 'APT40', origin: 'China', mitre: 'G0065', aliases: ['APT40', 'APT 40', 'Gingham Typhoon', 'Leviathan', 'Kryptonite Panda', 'TEMP.Periscope'] },
  { name: 'APT31', origin: 'China', aliases: ['APT31', 'APT 31', 'Violet Typhoon', 'Zirconium', 'Judgment Panda'] },
  { name: 'APT10', origin: 'China', mitre: 'G0045', aliases: ['APT10', 'APT 10', 'Stone Panda', 'MenuPass'] },
  { name: 'Charcoal Typhoon', origin: 'China', aliases: ['Charcoal Typhoon', 'Chromium APT', 'ControlX'] },
  { name: 'Earth Lamia', origin: 'China', aliases: ['Earth Lamia'] },
  { name: 'UNC5221', origin: 'China', aliases: ['UNC5221', 'UNC5337'] },
  { name: 'UNC3886', origin: 'China', aliases: ['UNC3886'] },
  { name: 'Storm-0558', origin: 'China', aliases: ['Storm-0558'] },
  { name: 'MuddyWater', origin: 'Iran (MOIS)', mitre: 'G0069', aliases: ['MuddyWater', 'Mango Sandstorm', 'Static Kitten', 'Seedworm', 'TEMP.Zagros'] },
  { name: 'APT33', origin: 'Iran', mitre: 'G0064', aliases: ['APT33', 'APT 33', 'Peach Sandstorm', 'Elfin', 'Refined Kitten', 'HOLMIUM'] },
  { name: 'APT34', origin: 'Iran', mitre: 'G0049', aliases: ['APT34', 'APT 34', 'OilRig', 'Hazel Sandstorm', 'Helix Kitten', 'Earth Simnavaz'] },
  { name: 'APT35', origin: 'Iran (IRGC)', mitre: 'G0059', aliases: ['APT35', 'APT 35', 'APT42', 'APT 42', 'Charming Kitten', 'Mint Sandstorm', 'Phosphorus', 'Educated Manticore', 'TA453', 'Magic Hound'] },
  { name: 'CyberAv3ngers', origin: 'Iran (IRGC)', aliases: ['CyberAv3ngers', 'Cyber Av3ngers', 'Storm-0784'] },
  { name: 'Handala', origin: 'Iran', aliases: ['Handala'] },
  { name: 'Scattered Spider', origin: 'Cybercrime', mitre: 'G1015', aliases: ['Scattered Spider', 'Octo Tempest', 'UNC3944', '0ktapus', 'Muddled Libra', 'Starfraud'] },
  { name: 'ShinyHunters', origin: 'Cybercrime', aliases: ['ShinyHunters', 'UNC6040', 'Scattered LAPSUS$ Hunters'] },
  { name: 'LAPSUS$', origin: 'Cybercrime', mitre: 'G1004', aliases: ['LAPSUS$', 'Strawberry Tempest'] },
  { name: 'FIN7', origin: 'Cybercrime', mitre: 'G0046', aliases: ['FIN7', 'Carbanak', 'Sangria Tempest'] },
  { name: 'FIN8', origin: 'Cybercrime', mitre: 'G0061', aliases: ['FIN8'] },
  { name: 'TA505', origin: 'Cybercrime', mitre: 'G0092', aliases: ['TA505', 'Lace Tempest'] },
  { name: 'Evil Corp', origin: 'Cybercrime (Russia)', mitre: 'G0119', aliases: ['Evil Corp', 'Indrik Spider', 'Manatee Tempest'] },
  { name: 'TeamTNT', origin: 'Cybercrime', aliases: ['TeamTNT'] },
  { name: 'Transparent Tribe', origin: 'Pakistan', mitre: 'G0134', aliases: ['Transparent Tribe', 'APT36', 'APT 36', 'Mythic Leopard', 'ProjectM'] },
  { name: 'SideWinder', origin: 'India', mitre: 'G0121', aliases: ['SideWinder', 'Rattlesnake APT', 'Razor Tiger'] },
  { name: 'Patchwork', origin: 'India', mitre: 'G0040', aliases: ['Patchwork', 'Dropping Elephant', 'Hangover Group'] },
  { name: 'Bitter APT', origin: 'South Asia', aliases: ['Bitter APT', 'APT-C-08', 'T-APT-17'] },
  { name: 'Equation Group', origin: 'United States', mitre: 'G0020', aliases: ['Equation Group'] },
  { name: 'Killnet', origin: 'Hacktivist (pro-Russia)', aliases: ['Killnet'] },
  { name: 'NoName057(16)', origin: 'Hacktivist (pro-Russia)', aliases: ['NoName057(16)', 'NoName057', 'NoName 057'] },
  { name: 'Anonymous Sudan', origin: 'Hacktivist', aliases: ['Anonymous Sudan', 'Storm-1359'] },
  { name: 'Cyber Army of Russia', origin: 'Hacktivist (pro-Russia)', aliases: ['Cyber Army of Russia'] },
];

export const MALWARE = [
  'Lumma Stealer|LummaC2|Lumma', 'RedLine Stealer|RedLine', 'Vidar', 'StealC', 'Raccoon Stealer', 'Atomic Stealer|AMOS', 'Rhadamanthys', 'Meduza Stealer', 'Acreed',
  'AsyncRAT', 'Remcos', 'XWorm', 'NetSupport RAT', 'DarkGate', 'njRAT', 'Quasar RAT|QuasarRAT', 'PlugX', 'ShadowPad', 'Gh0st RAT', 'SparkRAT', 'DCRat',
  'QakBot|Qbot', 'Emotet', 'IcedID', 'Latrodectus', 'Pikabot', 'Bumblebee', 'SocGholish', 'GootLoader', 'Matanbuchus', 'HijackLoader', 'SmokeLoader', 'Amadey',
  'Cobalt Strike', 'Sliver', 'Brute Ratel', 'Havoc C2', 'Mythic C2', 'Metasploit',
  'Mirai', 'Gafgyt', 'Aisuru', 'Kimwolf', 'Mozi', 'Raptor Train', 'BadBox',
  'Pegasus', 'Predator spyware', 'Graphite spyware|Paragon Graphite',
  'Xenomorph', 'Anatsa', 'SpyNote', 'Crocodilus', 'Godfather', 'TrickMo',
  'BPFDoor', 'Winnti', 'KV-botnet', 'COATHANGER', 'Brickstorm',
  'ClickFix', 'FakeUpdates', 'Shai-Hulud', 'GlassWorm',
].map(s => { const names = s.split('|'); return [names[0], names]; });

const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// \b does not work next to "$" or ")", so use look-arounds on word characters instead.
export const aliasRegex = aliases => new RegExp(`(?<![\\w-])(?:${aliases.map(a => escapeRe(a).replace(/ /g, '[ -]?')).join('|')})(?![\\w-])`, 'i');
export const ACTORS = ACTOR_INFO.map(a => [a.name, aliasRegex(a.aliases)]);
export const MALWARE_RE = MALWARE.map(([name, names]) => [name, aliasRegex(names)]);
export const slug = s => s.toLowerCase().replace(/\$/g, 's').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

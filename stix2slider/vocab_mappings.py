# STIX

# Limited in STIX 2.0, no labels available.
COA_LABEL_MAP = \
    {
        "perimeter-blocking": "Perimeter Blocking",
        "internal-blocking": "Internal Blocking",
        "redirection": "Redirection",
        "redirection-honey-pot": "Redirection (Honey Pot)",
        "hardening": "Hardening",
        "patching": "Patching",
        "eradication": "Eradication",
        "rebuilding": "Rebuilding",
        "training": "Training",
        "monitoring": "Monitoring",
        "physical-access-restrictions": "Physical Access Restrictions",
        "logical-access-restrictions": "Logical Access Restrictions",
        "public-disclosure": "Public Disclosure",
        "diplomatic-actions": "Diplomatic Actions",
        "policy-actions": "Policy Actions",
        "other": "Other",
    }

INDICATOR_LABEL_MAP = \
    {
        "anonymization": "Anonymization",
        "compromised-pki-certificate": "Compromised PKI Certificate",
        "login-name": "Login Name",
        "malware-artifacts": "Malware Artifacts",
        "malicious-email": "Malicious E-mail",
        "exfiltration": "Exfiltration",
        "command-and-control": "C2",
        "ip-watchlist": "IP Watchlist",
        "domain-watchlist": "Domain Watchlist",
        "url-watchlist": "URL Watchlist",
        "file-hash-watchlist": "File Hash Watchlist",
        "imei-watchlist": "IMEI Watchlist",
        "imsi-watchlist": "IMSI Watchlist",
        "host-characteristics": "Host Characteristics",
    }

INFRASTRUCTURE_LABELS_MAP = {
    # "amplification": "",
    "anonymization": "Anonymization",
    # "botnet": ,
    "command-and-control": "Hosting - Compromised Server",
    # "exfiltration"
    # "hosting-malware": "Hosting",
    # "hosting-target-lists": "Hosting",
    # phishing
    # reconnaissance
    # staging
    # undefined
}

MALWARE_LABELS_MAP = \
    {
        "adware": "Adware",
        # "backdoor":,
        "bot": "Bot",
        "ddos": "DoS / DDoS",
        # "dropper":,
        "exploit-kit": "Exploit Kits",
        "keylogger": "Bot - Credential Theft",
        "ransomware": "Ransomware",
        "remote-access-trojan": "Remote Access Trojan",
        # "resource-exploitation":,
        "rogue-security-software": "Rogue Antivirus",
        "rootkit": "Rootkit",
        # "screen-capture":,
        # "spyware":, "
        # "trojan":,
        # "virus":,
        # "worm":
    }

# "automated-transfer-scripts""Automated Transfer Scripts": ,
#  "Dialer": "dialer",
# "Bot - DDoS": "bot-ddos",
# "Bot - Loader": "bot-loader",
# "Bot - Spam": "bot-spam",
# "DoS / DDoS - Participatory": "dos-ddos-participatory",
# "DoS / DDoS - Script": "dos-ddos-script",
# "DoS / DDoS - Stress Test Tools": "dos-ddos-stress-test-tools",
# "POS / ATM Malware": "pos-atm-malware",


ROLES_MAP = \
    {

    }

SECTORS_MAP = \
    {
        "chemical": "Chemical Sector",
        "commercial": "Commercial Facilities Sector",
        "communications": "Communications Sector",
        "manufacturing": "Critical Manufacturing Sector",
        "dams": "Dams Sector",
        "defense": "Defense Industrial Base Sector",
        "emergency-services": "Emergency Services Sector",
        "energy": "Energy Sector",
        "financial-services": "Financial Services Sector",
        "agriculture": "Food and Agriculture Sector",
        "government-facilities-sector": "Government Facilities Sector",
        "healthcare": "Healthcare and Public Health Sector",
        "technology": "Information Technology Sector",
        "nuclear": "Nuclear Reactors, Materials, and Waste Sector",
        "other": "Other",
        "transportation": "Transportation Systems Sector",
        "water": "Water and Wastewater Systems Sector",
    }

THREAT_ACTOR_LABEL_MAP = \
    {
        # "Cyber Espionage Operations": "cyber-espionage-operations",
        # "Hacker": "hacker",
        # "Hacker - White hat": "hacker-white-hat",
        # "Hacker - Gray hat": "hacker-gray-hat",
        # "Hacker - Black hat": "hacker-black-hat",
        # "Hacktivist": "hactivist",
        # "State Actor / Agency": "nation-state",
        # "eCrime Actor - Credential Theft Botnet Operator": "ecrime-actor-botnet-operator",
        # "eCrime Actor - Credential Theft Botnet Service": "ecrime-actor-botnet-service",
        # "eCrime Actor - Malware Developer": "ecrime-actor-malware-developer",
        # "eCrime Actor - Money Laundering Network": "ecrime-actor-money-laundering-network",
        # "eCrime Actor - Organized Crime Actor": "ecrime-actor-organized-crime-actor",
        # "eCrime Actor - Spam Service": "ecrime-actor-spam-service",
        # "eCrime Actor - Traffic Service": "ecrime-actor-traffic-service",
        # "eCrime Actor - Underground Call Service": "ecrime-actor-underground-call-service",
        # "Insider Threat": "insider-threat",
        # "Disgruntled Customer / User": "disgruntled-customer-user",

        "activist": "Hacktivist",
        # competitor,
        "crime-syndicate": "eCrime Actor - Organized Crime Actor",
        # criminal,
        "hacker": "Hacker",
        # insider-accidental,
        "insider-disgruntled": "Insider Threat",
        "nation-state": "State Actor / Agency",
        # sensationalist,
        # spy,
        # terrorist
    }

ATTACK_MOTIVATION_MAP = \
    {
        # "Ideological": "ideology",
        # "Ideological - Anti-Corruption": "ideology-anti-corruption",
        # "Ideological - Anti-Establishment": "ideology-anti-establishment",
        # "Ideological - Environmental": "ideology-environmental",
        # "Ideological - Ethnic / Nationalist": "ideology-ethnic-nationalist",
        # "Ideological - Information Freedom": "ideology-information-freedom",
        # "Ideological - Religious": "ideology-religious",
        # "Ideological - Security Awareness": "ideology-security-awareness",
        # "Ideological - Human Rights": "ideology-human-rights",
        # "Ego": "personal-satisfaction",
        # "Financial or Economic": "financial-or-economic-gain",
        # "Military": "military",
        # "Opportunistic": "opportunistic",
        # "Political": "political",

        # accidental,
        # coercion,
        # dominance,
        "ideology": "Ideological",
        "notoriety": "Ego",
        "organizational-gain": "Financial or Economic",
        "personal-gain": "Financial or Economic",
        "personal-satisfaction": "Ego",
        # revenge,
        # unpredictable
    }

THREAT_ACTOR_SOPHISTICATION_MAP = \
    {
        "innovator": "Innovator",
        "expert": "Expert",
        "advanced": "Expert",
        "intermediate": "Practitioner",
        "minimal": "Novice",
        "none": "Aspirant",
    }

TOOL_LABELS_MAP = \
    {
        # "malware": "Malware",
        # "penetration-testing": "Penetration Testing",
        # "port-scanning": "Port Scanner",
        # "traffic-scanning": "Traffic Scanner",
        "vulnerability-scanning": "Vulnerability Scanner",
        # "application-scanning": "Application Scanner",
        "credential-exploitation": "Password Cracking",

        # denial-of-service
        # exploitation
        # information-gathering
        # network-capture
        # remote-access
    }


REPORT_LABELS_MAP = \
    {
        "collective-threat-intelligence": "Collective Threat Intelligence",
        "threat-report": "Threat Report",
        "indicators": "Indicators",
        "indicator-phising": "Indicators - Phishing",
        "indicator-watchlist": "Indicators - Watchlist",
        "indicator-malware-artifacts": "Indicators - Malware Artifacts",
        "indicator-network-artifacts": "Indicators - Network Activity",
        "indicator-endpoint-characteristics": "Indicators - Endpoint Characteristics",
        "campaign-characterization": "Campaign Characterization",
        "threat-actor-characterization": "Threat Actor Characterization",
        "exploit-characterization": "Exploit Characterization",
        "attack-pattern-characterization": "Attack Pattern Characterization",
        "malware-characterization": "Malware Characterization",
        "ttp-infrastructure": "TTP - Infrastructure",
        "ttp-tools": "TTP - Tools",
        "courses-of-action": "Courses of Action",
        "incident": "Incident",
        "observations": "Observations",
        "observations-email": "Observations - Email",
        "malware-samples": "Malware Samples",
    }

ATTACK_RESOURCE_LEVEL_MAPPING = {
    "individual": "",
    "club": "",
    "contest": "",
    "team": "",
    "organization": "",
    "government": ""
}

# CybOX

WINDOWS_PEBINARY = \
    {

    }

SERVICE_START_TYPE = \
    {

    }

SERVICE_TYPE = \
    {

    }

SERVICE_STATUS = \
    {

    }

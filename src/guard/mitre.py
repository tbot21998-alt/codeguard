from guard.schema import MitreReference

ATTACK = "https://attack.mitre.org/"
CWE = "https://cwe.mitre.org/data/definitions/"

# Primary ATT&CK technique and CWE weakness for each CodeGuard category. These are the closest
# single mappings, not an exhaustive classification of every finding in the category.
MITRE_MAPPING = {
    "secret_access": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1552", "technique_name": "Unsecured Credentials",
        "cwe_id": "CWE-522", "url": ATTACK + "techniques/T1552/",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel",
        "cwe_id": "CWE-200", "url": ATTACK + "techniques/T1041/",
    },
    "destructive_command": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1485", "technique_name": "Data Destruction",
        "cwe_id": "CWE-78", "url": ATTACK + "techniques/T1485/",
    },
    "persistence_or_privesc": {
        "tactic": "Persistence / Privilege Escalation", "tactic_id": "TA0003 / TA0004",
        "technique_id": "T1547", "technique_name": "Boot or Logon Autostart Execution",
        "cwe_id": "CWE-269", "url": ATTACK + "techniques/T1547/",
    },
    "obfuscated_execution": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
        "cwe_id": "CWE-506", "url": ATTACK + "techniques/T1027/",
    },
    "dependency_risk": {
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "technique_id": "T1195.001", "technique_name": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
        "cwe_id": "CWE-1357", "url": ATTACK + "techniques/T1195/001/",
    },
    "resource_exhaustion": {
        "tactic": "Impact", "tactic_id": "TA0040",
        "technique_id": "T1499", "technique_name": "Endpoint Denial of Service",
        "cwe_id": "CWE-400", "url": ATTACK + "techniques/T1499/",
    },
    "ssrf_network_exfil": {
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "technique_id": "T1552.005", "technique_name": "Cloud Instance Metadata API",
        "cwe_id": "CWE-918", "url": ATTACK + "techniques/T1552/005/",
    },
    "ai_targeted_instructions": {
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "technique_id": "T1562.001", "technique_name": "Impair Defenses: Disable or Modify Tools",
        "cwe_id": "CWE-77", "url": ATTACK + "techniques/T1562/001/",
    },
}


def mitre_for(category):
    return MitreReference(category=category, **MITRE_MAPPING[category])


def techniques_for(categories):
    """Unique references, one per category, in sorted category order. Empty input gives an empty list."""
    return [mitre_for(category) for category in sorted(set(categories))]

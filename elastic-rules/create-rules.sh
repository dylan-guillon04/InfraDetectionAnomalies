#!/usr/bin/env bash
# Règles de détection custom Elastic Security — à lancer sur l'hôte.
# Prérequis : avoir ouvert une fois Security → Alerts dans Kibana (initialise l'index des alertes).
# Idempotent : chaque règle a un rule_id fixe ; une règle déjà présente répond "already exists".
set -euo pipefail

KBN="http://localhost:5601"

# Mot de passe "elastic" lu depuis elk/.env (jamais en clair dans le dépôt)
# (surchargeable : ENV_FILE=../elk/.env bash create-rules.sh, cf. docs/00-lancer-le-lab.md)
ENV_FILE="${ENV_FILE:-$(dirname "$0")/../elk/.env}"
ELASTIC_PASSWORD="$(grep -E '^ELASTIC_PASSWORD=' "$ENV_FILE" | cut -d= -f2)"
: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD introuvable dans $ENV_FILE}"
AUTH="elastic:$ELASTIC_PASSWORD"

create_rule() {
  echo "== $1"
  curl -s -u "$AUTH" -X POST "$KBN/api/detection_engine/rules" \
    -H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' -H 'Content-Type: application/json' \
    -d "$2" | grep -oE '"(rule_id|name|message)":"[^"]*"' | head -2
  echo
}

# Promotion des alertes Suricata (tous scénarios réseau)
# Suricata détecte et écrit ses alertes dans eve.json → Elasticsearch, mais la page
# Security → Alerts n'affiche que les alertes créées par des règles Elastic.
# Cette règle "promeut" chaque alerte Suricata en alerte Elastic Security :
# même nom que la signature Suricata, sévérité reprise de Suricata (1 = haute).
create_rule "Promotion Suricata" '{
  "rule_id": "lab-suricata-promotion",
  "name": "Lab - Alerte Suricata (IDS réseau)",
  "description": "Reprend chaque alerte levée par Suricata comme alerte Elastic Security. Le nom de l alerte est celui de la signature Suricata.",
  "references": ["https://github.com/dylan-guillon04/InfraDetectionAnomalies/blob/main/docs/3-attaques/00-scenarios.md"],
  "type": "query",
  "index": ["logs-suricata.eve-*"],
  "language": "kuery",
  "query": "event.kind:\"alert\"",
  "rule_name_override": "rule.name",
  "severity": "medium",
  "severity_mapping": [
    {"field": "event.severity", "operator": "equals", "value": "1", "severity": "high"},
    {"field": "event.severity", "operator": "equals", "value": "2", "severity": "medium"},
    {"field": "event.severity", "operator": "equals", "value": "3", "severity": "low"}
  ],
  "risk_score": 47,
  "max_signals": 1000,
  "interval": "1m",
  "from": "now-2m",
  "tags": ["Lab IDS", "Suricata", "Promotion"],
  "enabled": true
}'

# Scénario 1 — Brute-force SSH (MITRE T1110.001)
# Seuil : 10 échecs d'authentification SSH en 1 minute pour un même couple IP source + compte.
# Les règles Elastic équivalentes supposent un Elastic Agent (host.id, 60 échecs en 30 s) :
# cette règle est calibrée pour le lab et pour les champs produits par syslog-ng + intégration System.
create_rule "Brute-force SSH" '{
  "rule_id": "lab-ssh-bruteforce",
  "name": "Lab - Brute-force SSH (échecs répétés)",
  "description": "Au moins 10 échecs d authentification SSH en 1 minute depuis une même IP vers un même compte. Tentative de devinette de mot de passe (hydra, medusa...).",
  "references": ["https://github.com/dylan-guillon04/InfraDetectionAnomalies/blob/main/docs/3-attaques/01-brute-force-ssh.md"],
  "type": "threshold",
  "index": ["logs-system.auth-*"],
  "language": "kuery",
  "query": "event.category:\"authentication\" and event.action:\"ssh_login\" and event.outcome:\"failure\"",
  "threshold": {"field": ["source.ip", "user.name"], "value": 10},
  "severity": "high",
  "risk_score": 73,
  "interval": "1m",
  "from": "now-2m",
  "tags": ["Lab IDS", "Scenario 1", "Credential Access"],
  "threat": [{
    "framework": "MITRE ATT&CK",
    "tactic": {"id": "TA0006", "name": "Credential Access", "reference": "https://attack.mitre.org/tactics/TA0006/"},
    "technique": [{"id": "T1110", "name": "Brute Force", "reference": "https://attack.mitre.org/techniques/T1110/",
      "subtechnique": [{"id": "T1110.001", "name": "Password Guessing", "reference": "https://attack.mitre.org/techniques/T1110/001/"}]}]
  }],
  "enabled": true
}'

# Scénario 3 — Scan de ports (MITRE T1046)
# Seuil : une même IP source touche plus de 50 ports TCP distincts de la victime.
# Basé sur les événements "flow" de Suricata : pas besoin de signature de scan.
# Fenêtre de 6 min car Suricata n'écrit un flux qu'à son expiration (≈ 1 min pour un SYN sans réponse).
create_rule "Scan de ports" '{
  "rule_id": "lab-port-scan",
  "name": "Lab - Scan de ports TCP depuis une seule source",
  "description": "Une même IP source a contacté plus de 50 ports TCP distincts de la victime. Signature typique d un scan nmap (reconnaissance).",
  "references": ["https://github.com/dylan-guillon04/InfraDetectionAnomalies/blob/main/docs/3-attaques/03-scan-de-ports.md"],
  "type": "threshold",
  "index": ["logs-suricata.eve-*"],
  "language": "kuery",
  "query": "event.dataset:\"suricata.eve\" and network.transport:\"tcp\" and destination.ip:\"10.10.10.10\"",
  "threshold": {
    "field": ["source.ip"],
    "value": 1,
    "cardinality": [{"field": "destination.port", "value": 50}]
  },
  "severity": "medium",
  "risk_score": 47,
  "interval": "1m",
  "from": "now-6m",
  "tags": ["Lab IDS", "Scenario 3", "Reconnaissance"],
  "threat": [{
    "framework": "MITRE ATT&CK",
    "tactic": {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
    "technique": [{"id": "T1046", "name": "Network Service Discovery", "reference": "https://attack.mitre.org/techniques/T1046/"}]
  }],
  "enabled": true
}'

# Scénario 2 — Attaque web sur DVWA (SQLi, LFI, outils d'attaque)
# Requête sur les logs d'accès nginx parsés en ECS.
create_rule "Attaque web" '{
  "rule_id": "lab-web-attack",
  "name": "Lab - Tentative d attaque web (SQLi, LFI, scanner)",
  "description": "Requête HTTP contenant un motif d injection SQL, de traversée de répertoire, ou émise par un outil d attaque connu (sqlmap, Nikto).",
  "references": ["https://github.com/dylan-guillon04/InfraDetectionAnomalies/blob/main/docs/3-attaques/02-attaque-web.md"],
  "type": "query",
  "index": ["logs-nginx.access-*"],
  "language": "kuery",
  "query": "event.dataset:\"nginx.access\" and (url.original:(*UNION* or *union* or *%27* or *OR%201=1* or *../* or *etc/passwd*) or user_agent.original:(*sqlmap* or *Nikto* or *nikto*))",
  "severity": "high",
  "risk_score": 73,
  "interval": "1m",
  "from": "now-2m",
  "tags": ["Lab IDS", "Scenario 2", "Web"],
  "threat": [{
    "framework": "MITRE ATT&CK",
    "tactic": {"id": "TA0001", "name": "Initial Access", "reference": "https://attack.mitre.org/tactics/TA0001/"},
    "technique": [{"id": "T1190", "name": "Exploit Public-Facing Application", "reference": "https://attack.mitre.org/techniques/T1190/"}]
  }],
  "enabled": true
}'

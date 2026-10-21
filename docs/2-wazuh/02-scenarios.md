# Partie 2.2 — Les cinq scénarios d'intrusion

Chaque scénario est décrit selon la même trame : objectif de l'attaquant, justification du choix, attaque rejouable, logs concernés, détection attendue puis obtenue.

**Justification d'ensemble.** Les cinq scénarios suivent les étapes d'une intrusion réelle (référentiel MITRE ATT&CK) :

1. **Reconnaissance** : le scan de ports (3).
2. **Accès initial** : le brute-force SSH (1) et l'attaque web (2).
3. **Persistance** : la modification de fichiers sensibles (4).
4. **Élévation de privilèges et charge malveillante** : le scénario 5.

Ils sollicitent volontairement des sources de logs différentes (authentification, web, réseau, système de fichiers), pour montrer la couverture de la plateforme.

| # | Scénario | Étape ATT&CK | Source principale | État |
| --- | --- | --- | --- | --- |
| 1 | Brute-force SSH | Accès aux identifiants (T1110.001) | `auth.log` via syslog-ng | ✅ |
| 2 | Attaque web | Accès initial (T1190) | nginx + Suricata | ✅ |
| 3 | Scan de ports | Reconnaissance (T1046) | Suricata | ✅ |
| 4 | Modification de fichiers sensibles | Persistance (T1505.003, T1136.001) | FIM (syscheck) | ✅ |
| 5 | Malware et élévation de privilèges | Exécution / persistance (T1105, T1136.001) | FIM + VirusTotal, `auth.log` | ✅ |

Les numéros de règles marqués *attendu* sont ceux des règles Wazuh correspondantes ; ils sont à confirmer avec l'identifiant réellement relevé lors du test.

Règle commune : **Kali attaque toujours l'adresse lab de la victime, `10.10.10.10`.**

---

## Scénario 1 — Brute-force SSH ✅

> Mode opératoire pas à pas (commandes, vérifications, preuves) : [attaque 1 — brute-force SSH](../3-attaques/01-brute-force-ssh.md).

**Objectif de l'attaquant.** Deviner le mot de passe d'un compte en essayant automatiquement une liste de mots de passe.

**Pourquoi ce scénario.** C'est l'attaque la plus fréquente contre un serveur exposé : tout service SSH ouvert sur Internet en subit en permanence. La détecter est le minimum attendu d'un système de surveillance.

**Attaque (Kali) :**

```bash
hydra -l victime -P /usr/share/wordlists/rockyou.txt -t 4 ssh://10.10.10.10
```

**Logs concernés.** `/var/log/auth.log` : une ligne `Failed password for victime from 10.10.10.30` par tentative. Le fichier est collecté par syslog-ng vers `security-collected.log`, lu par l'agent Wazuh.

**Détection obtenue :**

| Plateforme | Règle | Niveau |
| --- | --- | --- |
| Wazuh | **5763** — brute force SSH (échecs d'authentification répétés) | 10 |
| Wazuh | **2502** — échecs répétés, via le collecteur syslog-ng | 10 |
| ELK | « Lab - Brute-force SSH (échecs répétés) » : ≥ 10 échecs par IP et par compte | haute |

Les deux règles Wazuh se déclenchent par deux chemins différents. C'est la preuve que la collecte par syslog-ng fonctionne.

**Menace représentée.** Si un mot de passe faible cède, l'attaquant obtient un shell sur la machine.

**Réponse attendue de l'administrateur :**

- bloquer l'IP source ;
- vérifier qu'aucune connexion n'a réussi (`Accepted password` dans `auth.log`) ;
- imposer l'authentification par clé.

> 📸 `img/s1-wazuh-alertes.png` : alertes 5763 dans Threat Hunting · `img/s1-elk-alerte.png` : alerte dans Elastic Security

---

## Scénario 2 — Attaque web (injection SQL, LFI) ✅

> Mode opératoire pas à pas (commandes, vérifications, preuves) : [attaque 2 — attaque web](../3-attaques/02-attaque-web.md).

**Objectif de l'attaquant.** Exploiter une faille de l'application web pour lire la base de données (injection SQL) ou des fichiers du serveur (inclusion de fichier local).

**Pourquoi ce scénario.** Les applications web sont la surface d'attaque la plus exposée d'une organisation, et l'injection fait partie du Top 10 OWASP. DVWA, réglée en sécurité *Low*, reproduit ces failles.

**Attaque (Kali) :**

```bash
# Injection SQL manuelle
curl -s "http://10.10.10.10/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit" -b "security=low; PHPSESSID=<session>"
# Inclusion de fichier local
curl -s "http://10.10.10.10/vulnerabilities/fi/?page=../../../../../etc/passwd" -b "security=low; PHPSESSID=<session>"
# Scanners automatisés
nikto -h http://10.10.10.10
sqlmap -u "http://10.10.10.10/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=<session>" --batch
```

**Logs concernés.**

- `/var/log/nginx/access.log` : URL, user-agent, code retour.
- `eve.json` : alertes Suricata sur les signatures web ET Open.

**Détection attendue :**

| Plateforme | Règle | Remarque |
| --- | --- | --- |
| Wazuh | Règles web (groupe `web`, `attack`, `sql_injection`) | À vérifier : les lignes nginx arrivent préfixées d'un en-tête syslog par le collecteur. Si elles ne sont pas décodées, ajouter une source `localfile` directe sur `/var/log/nginx/access.log` |
| Wazuh | Alertes Suricata (*attendu* : 86601) | Signatures ET Open sur SQLi, LFI et scanners |
| ELK | « Lab - Tentative d'attaque web » | Motifs SQLi/LFI et user-agents `sqlmap`/`Nikto` |

**Menace représentée.** Vol de la base de données (comptes, mots de passe), lecture de fichiers système, puis exécution de code.

> 📸 `img/s2-wazuh.png` · `img/s2-elk.png`

---

## Scénario 3 — Scan de ports ✅

> Mode opératoire pas à pas (commandes, vérifications, preuves) : [attaque 3 — scan de ports](../3-attaques/03-scan-de-ports.md).

**Objectif de l'attaquant.** Cartographier les services ouverts de la victime avant de choisir une cible.

**Pourquoi ce scénario.** Le scan précède presque toute intrusion. Le détecter permet de repérer l'attaquant **avant** qu'il n'agisse.

**Attaque (Kali) :**

```bash
nmap -sS -p 1-1000 10.10.10.10
```

**Logs concernés.** `eve.json` : alertes et flux réseau vus par Suricata.

**Point technique.** Le jeu de règles ET Open ne détecte pas les scans de ports par défaut. Une signature Suricata custom est donc ajoutée (`/etc/suricata/rules/local.rules`) :

```
alert tcp any any -> $HOME_NET any (msg:"LAB SCAN Possible TCP SYN port scan (nmap -sS)"; flow:stateless; flags:S,12; detection_filter:track by_src, count 50, seconds 5; classtype:attempted-recon; sid:1000001; rev:1;)
```

Le seuil (plus de 50 paquets SYN en 5 secondes depuis une même source) dépasse le rythme d'un brute-force SSH, ce qui limite les faux positifs.

La signature est déclarée dans `rule-files` de `/etc/suricata/suricata.yaml` (chemin absolu, à côté de `suricata.rules`) et intégrée à l'image de la victime. Test du 21/10/2026 : `nmap -sS -p 1-1000` depuis Kali produit l'alerte dans `eve.json`, dans Elasticsearch, et déclenche les règles « Lab - Alerte Suricata » et « Lab - Scan de ports » d'Elastic Security.

`detection_filter` déclenche une alerte **pour chaque SYN au-delà du 50e** : un scan de 1 000 ports produit environ 950 alertes. Pour n'en garder qu'une par source et par fenêtre, on peut remplacer `detection_filter:…` par `threshold:type both, track by_src, count 50, seconds 5`.

**Détection attendue :**

| Plateforme | Règle |
| --- | --- |
| Wazuh | Alerte Suricata « LAB SCAN Possible TCP SYN port scan » (*attendu* : 86601) |
| ELK | « Lab - Scan de ports » : plus de 50 ports distincts touchés par une même IP, calculé sur les flux Suricata |

**Menace représentée.** Phase de reconnaissance. Seule, elle ne cause aucun dommage, mais elle annonce une attaque ciblée.

> 📸 `img/s3-wazuh.png`

---

## Scénario 4 — Modification de fichiers sensibles ✅

> Mode opératoire pas à pas (commandes, vérifications, preuves) : [attaque 4 — modification de fichiers](../3-attaques/04-modification-fichiers.md).

**Objectif de l'attaquant.** Une fois sur la machine, s'y maintenir : créer une porte dérobée (webshell) ou altérer les fichiers de comptes.

**Pourquoi ce scénario.** Contrairement aux scénarios précédents, celui-ci ne laisse aucune trace réseau : seule la surveillance de l'intégrité des fichiers le révèle. Il montre l'intérêt d'un HIDS en complément d'un IDS réseau.

**Attaque (sur la victime, en simulant un attaquant déjà présent) :**

```bash
# Altération d'un fichier de comptes
echo "pirate:x:0:0::/root:/bin/bash" >> /etc/passwd
# Dépôt d'un webshell dans le site
echo '<?php system($_GET["cmd"]); ?>' > /var/www/dvwa/shell.php
```

Penser à retirer la ligne ajoutée et le fichier après le test.

**Prérequis.** Surveillance temps réel activée sur `/etc` et `/var/www/dvwa` (voir [déploiement](01-deploiement.md#intégrité-des-fichiers-scénario-4)).

**Détection attendue :**

| Plateforme | Règle |
| --- | --- |
| Wazuh | Fichier modifié (*attendu* : 550) sur `/etc/passwd`, avec le contenu ajouté (`report_changes`) |
| Wazuh | Fichier ajouté (*attendu* : 554) : `/var/www/dvwa/shell.php` |

**Menace représentée.** Un compte d'UID 0 donne un accès root permanent ; un webshell permet d'exécuter des commandes à distance par simple requête HTTP.

> 📸 `img/s4-wazuh-fim.png`

---

## Scénario 5 — Malware et élévation de privilèges ✅

> Mode opératoire pas à pas (commandes, vérifications, preuves) : [attaque 5 — malware et élévation de privilèges](../3-attaques/05-malware-privileges.md).

**Objectif de l'attaquant.** Déposer un outil malveillant, puis se créer un compte privilégié.

**Pourquoi ce scénario.** Il combine deux capacités absentes d'ELK sans agent dédié : l'analyse de fichiers par renseignement sur les menaces (VirusTotal) et le suivi des comptes système.

**Attaque (sur la victime) :**

```bash
# Fichier de test EICAR : inoffensif, mais reconnu comme malveillant par tous les antivirus
curl -s -o /var/www/dvwa/eicar.com https://secure.eicar.org/eicar.com
# Création d'un compte avec droits sudo
useradd -m backdoor && usermod -aG sudo backdoor
```

**Prérequis.** Intégration VirusTotal configurée sur le manager (voir [déploiement](01-deploiement.md#notifications)).

**Détection attendue :**

| Plateforme | Règle |
| --- | --- |
| Wazuh | Fichier ajouté (FIM), puis VirusTotal : « X engines detected this file » (*attendu* : 87105) |
| Wazuh | Création d'un utilisateur et ajout au groupe `sudo` (règles de gestion des comptes, groupe `adduser`) |

**Menace représentée.** Exécution de code malveillant et maintien d'un accès administrateur.

> 📸 `img/s5-wazuh-virustotal.png` · `img/s5-wazuh-useradd.png`

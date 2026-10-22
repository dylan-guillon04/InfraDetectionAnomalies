# Attaque 3 — Scan de ports

> Mode opératoire du scénario 3. Contexte et justification : [scénarios](00-scenarios.md#scénario-3--scan-de-ports-). Prérequis : lab démarré (`lab/lab.sh up`).

- **But** : cartographier les ports TCP ouverts de la victime (MITRE T1046, reconnaissance), et le détecter côté **ELK** (règles « Lab - Scan de ports » et « Lab - Alerte Suricata ») et **Wazuh** (Suricata, `sid:1000001`).
- **Cible** : `10.10.10.10`.

## 1. Attaque (sur Kali)

```bash
# Scan SYN des 1000 premiers ports. -sS = demi-ouvert (ne termine pas la connexion).
nmap -sS -p 1-1000 10.10.10.10
# Variante plus agressive (tous les ports) : nmap -sS -p- 10.10.10.10
```

Le scan SYN envoie un `SYN` par port et attend le `SYN/ACK` sans finaliser la poignée de main : rapide et discret côté application, mais une même source touche des dizaines de ports en quelques secondes — c'est ce que les deux capteurs repèrent.

## 2. Vérifications

**Victime** — alerte de la signature custom dans `eve.json` :

```bash
sudo grep "LAB SCAN" /var/log/suricata/eve.json | tail
```

**Hôte** — flux Suricata ingérés dans Elasticsearch :

```bash
cd ~/cours/secu-info/projet-ids/elk
AUTH="elastic:$(grep ^ELASTIC_PASSWORD= .env | cut -d= -f2)"
curl -s --cacert ca.crt -u "$AUTH" \
  "https://localhost:9200/logs-suricata.eve-default/_count?q=event.dataset:suricata.eve%20AND%20network.transport:tcp%20AND%20destination.ip:10.10.10.10%20AND%20@timestamp:%3Enow-10m"
```

**Wazuh** (`wazuh.grdr.fr` → Threat Hunting, `agent.name: victime`) : alerte Suricata **« LAB SCAN Possible TCP SYN port scan »** (groupe `ids`).

**Kibana** (`localhost:5601`) :
- *Discover* : `event.dataset:"suricata.eve" and network.transport:"tcp" and destination.ip:"10.10.10.10"` — un flux par port touché.
- *Security → Alerts* : deux règles se déclenchent (laisser jusqu'à ~6 min, voir ci-dessous) :
  - **« Lab - Scan de ports »** : seuil + cardinalité (une IP source → plus de 50 ports distincts).
  - **« Lab - Alerte Suricata »** : promotion de l'alerte de la signature custom.

## 3. Résultat obtenu

Attaque jouée le 21/10/2026 (`nmap -sS -p 1-1000`), détection confirmée des deux côtés.

```bash
┌──(kali㉿kali)-[/tmp]
└─$ nmap -sS -p 1-1000 10.10.10.10
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-21 16:27 -0300
Nmap scan report for victime (10.10.10.10)
Host is up (0.00024s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 52:54:00:3F:44:0A (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds
```

`nmap` ne trouve que deux ports ouverts (22/SSH, 80/HTTP), mais pour le confirmer il a frappé les 1000 ports : c'est ce bruit qui est détecté.

![Dashboard Wazuh de l'agent victime : alerte Suricata « LAB SCAN Possible TCP SYN port scan » (règle 86601)](img/03-scan-de-ports/wazuh-threat-hunting.png)

**Wazuh** : la signature custom `sid:1000001` remonte via Suricata (règle `86601`), avec la source `10.10.10.30`.

![Discover de Kibana : des milliers de flux suricata.eve vers 10.10.10.10, un par port touché](img/03-scan-de-ports/discover-flux-suricata.png)

**Elastic (Discover)** : chaque port balayé produit un flux `suricata.eve` vers `10.10.10.10` (`destination.port` différent à chaque ligne). C'est ce volume brut que la règle de seuil **« Lab - Scan de ports »** agrège.

![Page Security → Alerts de Kibana : alerte de la règle de seuil « Lab - Scan de ports TCP depuis une seule source »](img/03-scan-de-ports/elastic-alerts-threshold.png)

**Elastic (Security → Alerts)** : la règle de seuil se déclenche à partir de ces flux agrégés (une même `source.ip` a dépassé 50 `destination.port` distincts). À ne pas confondre avec *Observability → Alerts*, qui ne montre pas les règles de détection.

## 4. Points d'attention

- **Deux chemins de détection en ELK.** La règle de **seuil** s'appuie sur les **flux** Suricata (aucune signature nécessaire) : aucun flux pris seul n'est suspect, c'est leur agrégation (> 50 ports par source) qui l'est. La règle de **promotion** remonte en plus l'alerte de la signature custom `sid:1000001`. Les deux sont utiles : la première résiste même si une signature manque, la seconde donne une alerte immédiate.
- **Délai d'alerte (~6 min).** Suricata n'écrit un flux qu'à son **expiration** (≈ 1 min pour un SYN resté sans réponse). La fenêtre de 6 min de la règle de seuil absorbe ce délai : l'alerte n'est donc pas instantanée. La signature custom, elle, déclenche dès le dépassement du seuil (> 50 SYN en 5 s).
- **Volume d'alertes de la signature.** `detection_filter` déclenche une alerte **par SYN au-delà du 50e** : un scan de 1000 ports produit ~950 alertes. Pour n'en garder qu'une par source et par fenêtre, remplacer `detection_filter:…` par `threshold:type both, track by_src, count 50, seconds 5` dans `local.rules`.
- **ET Open ne détecte pas les scans** par défaut : c'est la raison d'être de la signature custom et de la règle de flux. Détail dans [détection ELK](../1-elk/03-detection.md#scan-de-ports).


## 5. Réponse de l'administrateur

Cette section couvre la chaîne complète : **alerte → notification → explication → réponse**.

### 5.1 Alertes et notifications déclenchées

| Plateforme | Règle | Niveau par défaut | Notifiée (seuil ≥ 10) |
| --- | --- | --- | --- |
| Wazuh | **86601** — Suricata « LAB SCAN Possible TCP SYN port scan » (`sid:1000001`) | 3 | ❌ **non**, sans réglage |
| ELK | « Lab - Scan de ports » (> 50 ports distincts / IP) et « Lab - Alerte Suricata » | moyenne/haute | ❌ *Security → Alerts* uniquement |

Comme pour l'attaque web, l'alerte Suricata ne dépasse pas le seuil de notification par défaut. Un scan seul est une reconnaissance, pas une intrusion : on peut légitimement le notifier à un niveau plus bas (7), ou le réserver au tableau de bord. Pour **être prévenu** dès le scan, une règle locale rehausse l'alerte, et en **limite le volume** : `detection_filter` génère ~950 alertes pour 1 000 ports, il faut une seule notification.

```xml
<group name="local,recon,">
  <rule id="100030" level="10" frequency="1" timeframe="300" ignore="300">
    <if_sid>86601</if_sid>
    <field name="alert.signature">LAB SCAN</field>
    <same_source_ip />
    <description>Lab - Scan de ports TCP depuis une même source</description>
    <mitre><id>T1046</id></mitre>
  </rule>
</group>
```

`ignore="300"` : une fois déclenchée, la règle se tait 5 minutes pour la même source, ce qui évite la rafale de 950 messages. Valider avec `wazuh-logtest` avant `wazuh-control restart`. Le remplacement de `detection_filter` par `threshold` dans `local.rules` (voir points d'attention) agit au niveau Suricata, à la source.

### 5.2 Ce que reçoit l'administrateur

Message type (exemple indicatif) :

```
[Wazuh] Alerte niveau 10 — règle 100030
Description : Lab - Scan de ports TCP depuis une même source
Agent       : victime (004)
Source      : 10.10.10.30
Signature   : LAB SCAN Possible TCP SYN port scan (nmap -sS)
```

### 5.3 Explication pour l'administrateur

| Question | Réponse |
| --- | --- |
| **Que s'est-il passé ?** | Une même IP a envoyé plus de 50 paquets `SYN` en 5 secondes, vers des ports différents, sans finaliser la connexion (scan « demi-ouvert » `nmap -sS`). |
| **Pourquoi est-ce une alerte ?** | Aucun paquet isolé n'est suspect ; c'est l'agrégation qui l'est. Un client normal contacte 22, 80 ou 443, jamais 1 000 ports en une fraction de seconde. Les deux capteurs la confirment : la signature custom (immédiate) et la règle ELK sur les flux (retardée d'environ 6 min). |
| **Quelle gravité ?** | **Faible en soi, mais annonciatrice.** Le scan ne cause aucun dommage ; il révèle ce que l'attaquant sait désormais : ici **22/SSH et 80/HTTP**, soit les cibles des attaques 1 et 2. |
| **Alerte confirmée ou faux positif ?** | Scanner de vulnérabilités ou outil de supervision (Nessus, Zabbix, découverte réseau) → faux positif : vérifier l'IP. Source inconnue → reconnaissance hostile. |
| **Et après ?** | Surveiller **cette IP** : brute-force SSH ou attaque web dans les minutes ou heures suivantes. |

### 5.4 Actions de réponse

**1. Qualifier : la source est-elle légitime, et que fait-elle d'autre ?**

```bash
# Autres événements de la même IP sur la victime
sudo grep "10.10.10.30" /var/log/auth.log | tail
sudo grep "10.10.10.30" /var/log/nginx/access.log | tail
```

Dans Wazuh (*Threat Hunting*) ou Kibana (*Discover*) : filtrer sur `10.10.10.30` toutes sources confondues. **Une alerte de scan suivie d'un brute-force ou d'une attaque web depuis la même source est une intrusion en cours**, à traiter comme telle (voir [attaque 1](01-brute-force-ssh.md#5-réponse-de-ladministrateur) et [attaque 2](02-attaque-web.md#6-réponse-de-ladministrateur)).

**2. Contenir : bloquer la source.**

```bash
sudo ufw deny from 10.10.10.30
```

**3. Réduire la surface d'attaque : n'exposer que le nécessaire.**

```bash
sudo ss -tlnp                       # ports réellement à l'écoute (ici : 22, 80)
sudo ufw default deny incoming
sudo ufw allow from <IP_ADMIN> to any port 22   # SSH restreint aux administrateurs
sudo ufw allow 80/tcp
sudo ufw enable
```

Tout port ouvert découvert qui n'a pas de raison d'être (service oublié) est à fermer ou à arrêter.

**4. Corréler et surveiller.** Ajouter l'IP à une liste de surveillance : les alertes suivantes venant d'elle doivent être traitées en priorité. Le scan servant de signal précoce, c'est le moment de **renforcer** les défenses des services découverts (clés SSH, correctifs web) avant l'attaque.

## 6. Remise à zéro

```bash
cd ~/cours/secu-info/projet-ids/lab && ./lab.sh down && ./lab.sh reset && ./lab.sh up
```

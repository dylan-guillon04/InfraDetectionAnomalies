# Attaque 1 — Brute-force SSH

> Mode opératoire du scénario 1. Contexte et justification : [scénarios](../2-wazuh/02-scenarios.md#scénario-1--brute-force-ssh-). Prérequis : lab démarré (`lab/lab.sh up`).

- **But** : deviner un mot de passe SSH par essais répétés (MITRE T1110.001), et le détecter côté **Wazuh** (règles 5763 / 2502) et **ELK** (règle « Lab - Brute-force SSH »).
- **Cible** : `10.10.10.10`, compte `victime`.

## 1. Attaque (sur Kali)

```bash
# Liste dédiée : ~20 essais suffisent (seuil de détection = 10 échecs/min).
zcat /usr/share/wordlists/rockyou.txt.gz | head -20 > /tmp/lab-passwords.txt
# Variante "succès" : ajouter le vrai mot de passe en dernier — echo 'MDP' >> /tmp/lab-passwords.txt

hydra -l victime -P /tmp/lab-passwords.txt -t 4 -I ssh://10.10.10.10
```

## 2. Vérifications

**Victime** — échecs journalisés puis collectés par syslog-ng :

```bash
sudo grep "Failed password" /var/log/auth.log | tail
sudo grep "Failed password" /var/log/security-collected.log | tail   # chaîne Wazuh
```

**Hôte** — ingestion dans Elasticsearch :

```bash
cd ~/cours/secu-info/projet-ids/elk
AUTH="elastic:$(grep ^ELASTIC_PASSWORD= .env | cut -d= -f2)"
curl -s --cacert ca.crt -u "$AUTH" \
  "https://localhost:9200/logs-system.auth-default/_count?q=event.outcome:failure%20AND%20source.ip:10.10.10.30%20AND%20@timestamp:%3Enow-10m"
```

**Wazuh** (`wazuh.grdr.fr` → Threat Hunting, `agent.name: victime`) : règles **5763** et **2502** (niveau 10), `data.srcip: 10.10.10.30`.

**Kibana** (`localhost:5601`) :
- *Discover* : `event.dataset:"system.auth" and event.outcome:"failure" and source.ip:"10.10.10.30"`
- *Security → Alerts* : alerte **« Lab - Brute-force SSH »** (règle de seuil, 10 échecs/min par IP+compte ; laisser 1–2 min).

## 3. Résultat obtenu

Attaque jouée le 21/10/2026 (« échecs seuls »), détection confirmée des deux côtés.

![Sortie de hydra : 51 tentatives sur le compte victime, aucun mot de passe trouvé](img/01-brute-force-ssh/output-kali.png)

hydra affiche `all children were disabled` : c'est la pénalité OpenSSH 9.8 qui coupe les connexions (voir [ci-dessous](#openssh-98-et-la-pénalité-anti-brute-force)), pas un échec de la collecte.

![Dashboard Wazuh de l'agent victime : 182 échecs d'authentification](img/01-brute-force-ssh/wazuh-threat-hunting.png)

**Wazuh** : l'agent `victime` remonte **182 échecs d'authentification** (groupes `authentication_failed`, `sshd`, `pam`).

![Page Alerts de Kibana : alertes SSH, host victime à 99 %](img/01-brute-force-ssh/elastic-alerts.png)

**Elastic** : alertes concentrées à **99 % sur `victime`** ; l'alerte de seuil « Lab - Brute-force SSH » se déclenche sur les échecs ingérés.

## 4. OpenSSH 9.8 et la pénalité anti-brute-force

Debian 13 active par défaut les `PerSourcePenalties` d'OpenSSH 9.8 : après quelques échecs, sshd pénalise l'IP source et **rejette ses connexions suivantes** (`drop connection … penalty` dans `auth.log`), d'où le `all children were disabled` de hydra. Ces connexions rejetées ne produisent pas de `Failed password` et ne comptent pas pour la détection. **C'est un point à mentionner dans le rapport** : l'hôte freine nativement le brute-force.

| Option | Commande | Pour / contre |
| --- | --- | --- |
| **A — garder la pénalité** (défaut) | `hydra … -t 1 -W 1 …` (un essai à la fois) | réaliste ; détection plus lente à atteindre le seuil |
| **B — désactiver** | `PerSourcePenalties no` dans `sshd_config` + `systemctl restart ssh` | démo nette ; modifie la posture de la victime |

La détection fonctionne même en option A (test : 53 échecs ingérés, alerte ELK déclenchée). Pour rendre l'option B permanente, l'intégrer à l'image ([modifier l'image](../00-lancer-le-lab.md#modifier-limage-de-la-victime)).

> `could not resolve address: 10.10.10.10` = faute de frappe dans l'IP (souvent `O` au lieu de `0`).

## 5. Réponse de l'administrateur

Bloquer `10.10.10.30` · vérifier qu'aucune connexion n'a réussi (`Accepted password` dans `auth.log`) · imposer l'authentification par clé.

## 6. Remise à zéro

```bash
cd ~/cours/secu-info/projet-ids/lab && ./lab.sh down && ./lab.sh reset && ./lab.sh up
```

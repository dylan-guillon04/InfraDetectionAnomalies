# Partie 1.1 — Installation d'Elasticsearch et Kibana

> **Partie 1 — ELK.** Cette partie déploie la chaîne exigée par le sujet (syslog-ng → Elasticsearch → Kibana) et la rend fonctionnelle de bout en bout. Les scénarios d'intrusion sont ensuite menés sous Wazuh ([partie 2](../2-wazuh/01-deploiement.md)) ; le [bilan](../4-bilan-elk-vs-wazuh.md) explique ce choix.


> **Relancer le lab existant ?** Ce guide décrit l'installation initiale. Pour redémarrer la stack à partir des sauvegardes, utiliser `lab/lab.sh` : voir [lancer le lab](../0-lancer-le-lab.md#restaurer-nest-pas-réinstaller), qui liste les étapes ci-dessous déjà incluses dans la sauvegarde.

Elasticsearch et Kibana sont déployés en Docker sur l'**hôte Ubuntu** qui héberge les machines virtuelles du lab. Le fichier `elk/compose.yaml` est dérivé du compose officiel d'Elastic, ramené à un seul nœud.

## Pourquoi ce placement

| Option | Avantage | Inconvénient | Retenue |
| --- | --- | --- | --- |
| Sur la VM victime | Simple, tout en local | Un attaquant qui compromet la victime peut effacer ses traces ; la victime est alourdie | Non |
| Sur un VPS distant | Architecture réaliste | Transport TLS par Internet, certificats, pare-feu, dépendance réseau pendant la démo | Non |
| **Sur l'hôte, en Docker** | Logs hors de la machine attaquée, aucune dépendance Internet, RAM abondante | — | **Oui** |

## Sécurité de la stack

- **Authentification et TLS activés** (HTTP et transport). Elastic Security l'exige.
- Un conteneur éphémère `setup` génère une autorité de certification (CA) et le certificat d'Elasticsearch. Ce certificat est valide pour `es01`, `localhost`, `127.0.0.1` et **`192.168.122.1`**, l'adresse par laquelle la victime joint Elasticsearch.
- **Exposition minimale :**

| Service | Adresse d'écoute | Qui peut y accéder |
| --- | --- | --- |
| Elasticsearch | `127.0.0.1:9200` | l'hôte |
| Elasticsearch | `192.168.122.1:9200` | la victime, via le réseau NAT libvirt |
| Kibana | `127.0.0.1:5601` | le navigateur de l'hôte |

- Les secrets sont dans `elk/.env`, exclu du dépôt par `.gitignore`, comme les certificats générés.

## Prérequis sur l'hôte

```bash
docker compose version          # Docker Engine + plugin compose
sysctl vm.max_map_count         # doit être ≥ 262144
ip -4 addr show virbr0          # doit afficher 192.168.122.1 (virbr-ids avec lab/lab.sh)
```

Sur Ubuntu 24.04, `vm.max_map_count` vaut déjà 1 048 576 : aucun réglage n'est nécessaire. Sur un système où il serait plus bas :

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elastic.conf && sudo sysctl --system
```

## Étape 1 — Configuration

Depuis le dossier `elk/` :

```bash
cp .env.example .env
for v in ELASTIC_PASSWORD KIBANA_PASSWORD; do
  sed -i "s/^$v=.*/$v=$(openssl rand -hex 12)/" .env
done
for v in KIBANA_ENCRYPTION_KEY KIBANA_SAVEDOBJECTS_KEY KIBANA_REPORTING_KEY; do
  sed -i "s/^$v=.*/$v=$(openssl rand -hex 32)/" .env
done
chmod 600 .env
```

| Variable | Rôle |
| --- | --- |
| `STACK_VERSION` | Version d'Elasticsearch et Kibana (9.5.5) |
| `ELASTIC_PASSWORD` | Mot de passe du super-utilisateur `elastic` |
| `KIBANA_PASSWORD` | Mot de passe du compte technique `kibana_system` |
| `LAB_BIND_IP` | Adresse de l'hôte sur le réseau NAT libvirt (`192.168.122.1`) |
| `ES_MEM_LIMIT` / `KB_MEM_LIMIT` | Limites mémoire (4 Go et 2 Go ; le heap JVM vaut environ 50 % de la limite) |
| `KIBANA_*_KEY` | Clés de chiffrement exigées par Elastic Security (règles, alerting) |

Les mots de passe doivent être alphanumériques : le script du conteneur `setup` ne gère pas les caractères spéciaux.

## Étape 2 — Démarrage

```bash
docker compose up -d
docker compose ps
```

Résultat attendu après 2 à 3 minutes :

```
ids-elk-es01-1     ...   Up (healthy)   127.0.0.1:9200->9200/tcp, 192.168.122.1:9200->9200/tcp
ids-elk-kibana-1   ...   Up (healthy)   127.0.0.1:5601->5601/tcp
```

Le conteneur `setup` s'arrête une fois son travail fait ; `docker compose logs setup` doit se terminer par `Setup termine`.

Pour simplifier les commandes suivantes, on charge le mot de passe et on récupère la CA :

```bash
ES="https://localhost:9200"
AUTH="elastic:$(grep ^ELASTIC_PASSWORD= .env | cut -d= -f2)"
sudo cp certs/ca/ca.crt . && sudo chown $USER: ca.crt
```

## Étape 3 — Vérifications

**Depuis l'hôte :**

```bash
curl --cacert ca.crt -u $AUTH $ES
```

La réponse doit contenir `"number" : "9.5.5"`.

**Depuis la victime** (après avoir copié `ca.crt` dessus avec `scp`) :

```bash
curl --cacert /tmp/ca.crt -u elastic:<mot_de_passe> https://192.168.122.1:9200
```

On obtient la même réponse, ce qui valide le chemin réseau et le certificat.

**Depuis Kali**, la connexion doit échouer :

```bash
nc -zv -w3 192.168.122.1 9200
# (UNKNOWN) [192.168.122.1] 9200 (?) : Network is unreachable
```

**Kibana :** ouvrir `http://localhost:5601` et se connecter avec `elastic`. Sur l'écran d'accueil, choisir « Explore on my own ».

## Étape 4 — Réglage pour un nœud unique

Par défaut, chaque index demande une réplique, qui ne peut pas être placée sur un cluster d'un seul nœud. Le cluster resterait alors en état « jaune » en permanence. On fixe donc le nombre de répliques à zéro pour tous les data streams `logs-*` :

```bash
curl -s --cacert ca.crt -u $AUTH -X PUT "$ES/_component_template/logs@custom" \
  -H 'Content-Type: application/json' \
  -d '{"template":{"settings":{"index":{"number_of_replicas":0}}}}'
```

## Étape 5 — Installation des intégrations Elastic

Les intégrations sont installées **sans agent** : on ne récupère que leurs « assets ».

- **Pipelines d'ingestion** : ils convertissent une ligne de log brute au format ECS.
- **Templates d'index** : ils déclarent les types des champs.
- **Dashboards** prêts à l'emploi.

```bash
for p in system nginx suricata auditd; do
  curl -s -u $AUTH -X POST -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    "http://localhost:5601/api/fleet/epm/packages/$p" -d '{"force":true}' > /dev/null
done
```

| Intégration | Version | Data streams utilisés |
| --- | --- | --- |
| System | 3.0.0 | `logs-system.auth-default` |
| Nginx | 3.2.2 | `logs-nginx.access-default`, `logs-nginx.error-default` |
| Suricata | 7.0.10 | `logs-suricata.eve-default` |
| Auditd | 3.25.1 | `logs-auditd.log-default` (scénarios 4 et 5) |

Les erreurs `conflict` sur `logs-*` et `metrics-*` dans les logs Kibana sont sans conséquence : ces vues de données existent déjà.

Vérification dans Kibana : **Integrations → Installed integrations**.

## Test du parsing ECS

Avant de brancher syslog-ng, on injecte une ligne `auth.log` à la main :

```bash
curl -s --cacert ca.crt -u $AUTH -X POST "$ES/logs-system.auth-default/_doc?refresh=true" \
  -H 'Content-Type: application/json' \
  -d '{"input":{"type":"log"},"message":"Oct 15 16:06:42 victime sshd[4321]: Failed password for root from 10.10.10.30 port 50001 ssh2"}'
```

Le document stocké contient alors les champs ECS extraits par le pipeline :

```json
"source":  { "ip": "10.10.10.30", "port": 50001 },
"user":    { "name": "root" },
"process": { "name": "sshd", "pid": 4321 },
"event":   { "category": ["authentication"], "action": "ssh_login", "outcome": "failure" }
```

Sans le champ `"input":{"type":"log"}`, le pipeline ne parse rien (voir [pièges rencontrés](../5-pieges-rencontres.md)).

Ce data stream de test est ensuite supprimé, pour repartir propre :

```bash
curl -s --cacert ca.crt -u $AUTH -X DELETE "$ES/_data_stream/logs-system.auth-default"
```

## Arrêt et redémarrage

```bash
docker compose stop      # arrêt (les données sont conservées dans les volumes)
docker compose up -d     # redémarrage
docker compose down -v   # suppression complète, données comprises
```

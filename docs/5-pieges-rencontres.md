# Pièges rencontrés et solutions

Problèmes réellement rencontrés pendant la mise en place, avec leur diagnostic et leur solution. Les sections ELK concernent la [partie 1](1-elk/01-installation.md), les sections Wazuh la [partie 2](2-wazuh/01-deploiement.md).

## ELK : Elasticsearch et Kibana

| Symptôme | Cause | Solution |
| --- | --- | --- |
| `cp: cannot stat '.env.example'` après téléchargement des fichiers | Le navigateur renomme les fichiers commençant par un point (`_env.example`, `_gitignore`) | Renommer en `.env.example` et `.gitignore`. Vérifier `git status` avant tout commit : sans `.gitignore`, le `.env` et la CA partent sur GitHub |
| Commandes `curl` vers `localhost:9200` sans aucune sortie | Commandes lancées sur la victime au lieu de l'hôte (`localhost` = la machine courante) | Lancer les commandes ELK sur l'hôte, depuis `elk/` |
| Cluster en état « jaune » permanent | Chaque index demande une réplique, impossible à placer sur un nœud unique | Template `logs@custom` avec `number_of_replicas: 0` |
| Kibana bloqué sur « Ajouter des intégrations » | Écran d'accueil de la première connexion | Cliquer « Explore on my own » |
| Pas d'alertes visibles dans Discover | Discover affiche les logs bruts, pas les alertes des règles ; fenêtre de temps trop courte | Alertes dans Security → Détections → Alertes ; élargir la période |

## ELK : Pipelines d'ingestion (format ECS)

| Symptôme | Cause | Solution |
| --- | --- | --- |
| Documents `system.auth` stockés mais non parsés, sans aucune erreur | Le pipeline `logs-system.auth-3.0.0` n'aiguille le parsing que si `input.type` vaut `log` ou `journald` | syslog-ng ajoute `input.type=log` à chaque document |
| `@timestamp` décalé de plusieurs heures | Les lignes syslog n'ont pas de fuseau horaire : le pipeline les interprète en UTC | syslog-ng ajoute `event.timezone=${TZOFFSET}` |
| Requête Discover sur `data_stream.dataset:"system.auth"` sans résultat | Ce champ n'est pas renseigné : syslog-ng ne l'envoie pas et le template n'impose pas de valeur | Filtrer sur `event.dataset`, renseigné par le pipeline |
| Doute sur le parsing de `sshd-session` (OpenSSH ≥ 9.8, Debian 13) | Depuis OpenSSH 9.8, les sessions sont journalisées par `sshd-session` | Vérifié par `_simulate` : le pipeline parse correctement les deux formes. Aucune adaptation nécessaire |

Outil de diagnostic utile, pour tester un pipeline sans rien indexer :

```bash
curl -s --cacert ca.crt -u $AUTH -X POST "$ES/_ingest/pipeline/logs-system.auth-3.0.0/_simulate" \
  -H 'Content-Type: application/json' \
  -d '{"docs":[{"_source":{"input":{"type":"log"},"message":"<ligne de log>"}}]}'
```

## ELK : syslog-ng

| Symptôme | Cause | Solution |
| --- | --- | --- |
| Événements Suricata `stats` envoyés malgré le filtre | Avec `type(string)`, syslog-ng compare le message entier au motif | Ajouter `flags(substring)` |
| Conflit si deux configurations lisent le même fichier | syslog-ng identifie les sources par leur nom de fichier | `persist-name()` distinct dans chaque source |
| Conflit « systemd-journal namespace already in use » | `system()` déclaré dans une configuration additionnelle | Ne lire que des `file()` dans les configurations custom |

## ELK : Règles de détection Elastic Security

| Symptôme | Cause | Solution |
| --- | --- | --- |
| Règles SSH Elastic en échec : `Unknown column [host.os.type]` | Règles ES\|QL filtrant sur un champ posé par Elastic Agent, absent de nos documents | syslog-ng ajoute `host.os.type=linux` et `host.os.family=debian` |
| Règles EQL Elastic sans résultat | Corrélation `by host.id`, champ absent | syslog-ng ajoute `host.id` |
| Règle « External Alerts » introuvable | Absente de la version installée | Règle custom `lab-suricata-promotion` |
| Règles « Endpoint Security » et « Container Workload Protection » en warning | Activées par défaut, mais sans données | Les désactiver |
| Doublons de règles après relance du script | Règles créées sans identifiant fixe | `rule_id` fixe dans chaque règle : une relance répond « already exists » |

## Wazuh

| Symptôme | Cause | Solution |
| --- | --- | --- |
| Recherche de la règle 5712 sans résultat lors du brute-force SSH | Les identifiants de règles varient selon la version et le format du log | Règles observées sur ce lab : 5763 (brute force) et 2502 (via le collecteur) |
| Seules les alertes Suricata remontent, pas les flux ni les statistiques | Les décodeurs Wazuh ne retiennent que `event_type: alert` | Comportement voulu ; les flux sont exploités côté ELK |
| L'agent ne lit pas `eve.json` | Permissions du fichier | Vérifier `chmod 644` sur `eve.json` |
| Le dashboard affiche « API connections could be down » après changement du mot de passe `wazuh-wui` | Mot de passe à reporter à trois endroits : API, compose, `wazuh.yml` (montage depuis l'hôte) | Éditer `wazuh.yml` côté hôte, pas dans le conteneur |

## Réseau et système du lab

| Symptôme | Cause | Solution |
| --- | --- | --- |
| `dhclient: command not found` (Debian 13) | `dhclient` n'existe plus | `nmcli device connect <interface>` |
| Une carte réseau de la victime perd son IP | Un profil NetworkManager automatique passe d'une carte à l'autre | Deux profils fixes, attachés à leur interface (`ifname`) ; `ipv4.never-default yes` sur `lab-net` |
| `nginx` ou `syslog-ng` : « command not found » en root | `su root` garde un PATH incomplet (sans `/usr/sbin`) | Utiliser `su - root` |
| Suricata ne capture rien | Interface par défaut `eth0` inexistante | Remplacer par `enp7s0` dans `suricata.yaml`, valider avec `suricata -T` |
| nmap ne déclenche aucune alerte Suricata | Le jeu de règles ET Open ne couvre pas les scans de ports | Signature custom `sid:1000001` (scénario 3) |
| `/var/log/auth.log` absent | Debian 13 journalise dans journald par défaut | Installer un démon syslog qui écrit `auth.log` |
| Échec du `bind` d'Elasticsearch sur `192.168.122.1` | Le réseau libvirt `default` n'est pas encore actif | Lancer la stack ELK après le démarrage du lab |
| Kali joint Elasticsearch | Kali possède une carte sur le réseau NAT libvirt | Ne garder que la carte `lab-net` sur Kali |
| Les VM n'obtiennent aucune adresse IP (NetworkManager : `ip-config-unavailable`) | ufw actif sur l'hôte : il bloque DHCP et DNS sur les bridges libvirt | Règles ufw de [lancer le lab](0-lancer-le-lab.md#ufw) |
| Aucun log reçu dans Elasticsearch ni Wazuh après relance de la victime ; `auth.log` figé | syslog-ng démarré à la main mais jamais activé (`systemctl is-enabled syslog-ng` → `disabled`) : il ne redémarre pas au boot | `systemctl enable --now syslog-ng` sur la victime. Corrigé dans `debian13.qcow2` le 21/10/2026 |
| Agent Wazuh qui ne démarre pas, de façon aléatoire (`start operation timed out`, `Another instance is locking this process`) | VM éteinte pendant que `wazuh-control start` tournait : le verrou `/var/ossec/var/start-script-lock` reste sur le disque. Il bloque le démarrage dès que le PID qu'il contient existe au boot suivant | Supprimer le verrou. Intégré à l'image : un `ExecStartPre` le supprime à chaque démarrage du service |
| Relance de `lab.sh up` : `tar: certs/… Permission denied` | Le conteneur `setup` passe `elk/certs/` en root:root 750 | Corrigé dans `lab.sh` (teste seulement la présence du dossier) |
| `virsh define debian13.xml` échoue sur un autre PC | Type de machine `pc-q35-noble`, propre au QEMU d'Ubuntu | Utiliser les définitions portables de `lab/libvirt/` (machine `q35`), via `lab/lab.sh` ([lancer le lab](0-lancer-le-lab.md)) |

## Limites identifiées côté ELK

- **Dépendance aux champs posés par Elastic Agent.** Les règles Elastic supposent `host.id`, `host.os.type`, etc. Avec un autre collecteur, chaque règle doit être vérifiée.
- **L'API `_bulk` masque les rejets.** Elle répond « OK » même quand un document est refusé : la qualité du parsing doit être contrôlée à part.
- **Notifications limitées par la licence Basic** (voir [partie 1.3](1-elk/03-detection.md#notifications--limite-de-la-licence-gratuite)), alors que Wazuh les fournit gratuitement.
- **Le mot de passe syslog-ng est en clair** dans `elastic.conf`. C'est acceptable dans un lab isolé : le compte ne peut qu'écrire dans `logs-*`. En production, on utiliserait une clé d'API ou un fichier de secret protégé.

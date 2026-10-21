# Stack ELK (Elasticsearch + Kibana)

Configuration **de référence**, versionnée :

- `compose.yaml` — services Elasticsearch + Kibana (projet Docker `ids-elk`).
- `.env.example` — modèle de variables (versions, mots de passe). À copier en `.env` et remplir.

## Fichiers d'exécution — jamais versionnés

Fournis à part ou générés au premier démarrage, ignorés par git (voir `../.gitignore`) :

| Fichier | Rôle |
| --- | --- |
| `.env` | Mots de passe réels (copie remplie de `.env.example`) |
| `certs/`, `ca.crt` | Autorité et certificats TLS, créés au premier `up` par le conteneur `setup` |
| `elk-secrets.tgz` | Archive `.env` + certificats, pour rejouer le lab sans les régénérer |
| `esdata01.tgz`, `kibanadata.tgz` | Sauvegardes des volumes Docker (données Elasticsearch / Kibana) |

Ces fichiers lourds ou sensibles restent **hors dépôt**. `lab/lab.sh` les attend dans le dossier
pointé par `IDS_HOME` (par défaut la racine du dépôt ; voir `../lab/lab.conf.example`).
/home/mathieu/cours/secu-info/projet-ids/elk
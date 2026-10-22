# Bilan — ELK vs Wazuh, limites et perspectives

## Pourquoi on a basculé sur Wazuh

La chaîne ELK fonctionne (voir [partie 1](1-elk/03-detection.md#ce-que-la-partie-1-démontre)). Mais chaque étape a demandé un travail d'adaptation que Wazuh fournit d'origine. Le tableau ci-dessous ne s'appuie pas sur des fiches produit : il résume ce que nous avons **réellement fait** de chaque côté.

| Besoin | Avec ELK + Elastic Security (vécu) | Avec Wazuh (vécu) |
| --- | --- | --- |
| **Rendre les logs exploitables** | Installer quatre intégrations, puis découvrir par essais que le pipeline exige `input.type`, que l'heure est décalée sans `event.timezone`, et que les règles exigent `host.id` et `host.os.type` | Décodeurs intégrés : les lignes `auth.log` sont comprises dès l'enrôlement de l'agent |
| **Détecter un brute-force SSH** | Les règles Elastic échouent (`Unknown column`) ou sont calibrées pour la production : écriture d'une règle custom | Règle 5763 déclenchée sans aucun réglage |
| **Remonter les alertes Suricata** | Règle de « promotion » à écrire, la règle générique étant absente de la version installée | Décodeur Suricata intégré, alertes visibles directement |
| **Surveiller l'intégrité des fichiers** | auditd + intégration, ou Elastic Defend (agent + Fleet Server) | Module syscheck natif, quelques lignes de configuration |
| **Vérifier la conformité** | Non couvert en licence gratuite | Scan CIS automatique (42 % sur la victime) |
| **Notifier l'administrateur** | Connecteurs courriel, Slack et webhook payants ; essai de 30 jours ou script maison | Courriel et Slack natifs et gratuits |
| **Analyser un fichier suspect** | Pas d'équivalent sans Elastic Defend | Intégration VirusTotal native |

### En résumé

**ELK est une plateforme d'analyse de données : puissante, mais à construire.** Elasticsearch stocke, Kibana visualise, Elastic Security fournit un moteur de règles très riche (seuils, séquences EQL, ES|QL, plus de 2 000 règles). Mais tout cela suppose l'écosystème Elastic complet (Elastic Agent, Fleet, Defend), ou un important travail d'intégration quand on passe par un autre collecteur comme syslog-ng.

**Wazuh est une solution de sécurité prête à l'emploi.** Agent, décodeurs, règles, FIM, conformité, notifications et réponse active sont livrés ensemble. Pour un lab d'une machine à surveiller et cinq scénarios à démontrer, c'est l'outil le plus efficace.

Les deux ne s'opposent pas. Wazuh utilise lui-même un moteur dérivé d'Elasticsearch (OpenSearch) et une interface dérivée de Kibana. En production, on les combine souvent : Wazuh pour la détection sur les hôtes, une pile Elastic pour l'analyse à grande échelle.

## Ce qui a été conservé de la partie 1

- **syslog-ng** reste le collecteur sur la victime : il alimente à la fois Elasticsearch et le fichier lu par l'agent Wazuh.
- **Suricata** reste l'IDS réseau, et ses alertes remontent dans les deux plateformes.
- **La stack ELK** reste opérationnelle : les scénarios 1 à 3 y sont aussi détectés.

## Limites du projet

- **Un seul hôte surveillé.** La corrélation entre plusieurs machines (mouvement latéral) n'est pas démontrée.
- **Lab isolé et trafic non chiffré.** Suricata voit le HTTP en clair. Sur un site en HTTPS, il ne verrait plus le contenu des requêtes, et seuls les logs du serveur web resteraient exploitables.
- **Seuils calibrés pour le lab.** Les seuils (10 échecs SSH, 50 ports) conviennent à des attaques bruyantes. Une attaque lente (*low and slow*) passerait en dessous.
- **Signatures connues uniquement.** Suricata et les règles Wazuh détectent des motifs connus. Aucune détection comportementale ou par apprentissage automatique (payante chez Elastic) n'est mise en œuvre.
- **Serveur Wazuh sur un VPS partagé**, qui héberge d'autres services. En production, la plateforme de sécurité serait isolée.
- **Côté ELK, dépendance à des champs ajoutés à la main** : toute mise à jour des intégrations ou des règles Elastic peut casser la chaîne silencieusement, car l'API `_bulk` ne signale pas les rejets.

## Améliorations possibles

- **Réponse active Wazuh** : bloquer automatiquement l'IP d'un attaquant (règle `firewall-drop`) après un brute-force.
- **Scanner les images Docker** (Trivy), un angle mort de l'agent Wazuh, qui n'inventorie que les paquets de l'hôte.
- **Côté ELK, remplacer syslog-ng par Elastic Agent** : on retrouverait les règles Elastic sans adaptation, ainsi que l'EDR Elastic Defend.
- **Ajouter des sources** : DNS, pare-feu, journaux Windows, pour élargir la couverture.

## Veille technologique

- **Wazuh 5.0** est en préversion (alpha/beta) au moment du projet, d'où le choix de la branche stable 4.14.
- **Elastic** pousse l'Elastic Agent comme collecteur unique et le langage ES|QL pour ses règles. Sa documentation sur les règles prêtes à l'emploi suppose de plus en plus cet agent, ce que nous avons constaté.
- **OpenSearch**, le fork open source d'Elasticsearch sur lequel repose l'indexer Wazuh, évolue désormais indépendamment d'Elastic.
- **Les détections assistées par IA** (assistants d'investigation, découverte automatique d'attaques) apparaissent dans les SIEM du marché, Elastic Security compris.

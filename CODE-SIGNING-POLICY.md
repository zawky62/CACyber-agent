# Politique de signature du code — CACyber Agent

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## Ce qui est signé

Seul l'exécutable **CACyber-Agent.exe** est signé. Il est produit par l'intégration continue GitHub Actions
de ce dépôt public, à partir d'une étiquette de version (`v*`). Aucun binaire compilé sur un poste
personnel n'est signé.

Les outils tiers que l'agent utilise ne sont **ni modifiés, ni redistribués, ni signés** par ce projet :

| Outil | Rôle | Éditeur et signataire vérifié avant chaque exécution |
|---|---|---|
| Nmap | Découverte réseau | Nmap Software LLC (installé depuis nmap.org par l'utilisateur) |
| osquery | Inventaire local | osquery, a Series of LF Projects, LLC (Linux Foundation) |
| Npcap (option) | Pilote de capture | Insecure.Com LLC (installé depuis npcap.com par l'utilisateur) |

## Rôles

| Rôle | Personnes |
|---|---|
| Auteurs (committers) | Mainteneurs du dépôt GitHub |
| Relecteurs (reviewers) | Mainteneurs : toute modification passe par une demande de fusion relue |
| Approbateurs (approvers) | Mainteneurs : chaque demande de signature est approuvée manuellement dans SignPath |

Tous les membres de l'équipe utilisent l'authentification multifacteur sur GitHub et sur SignPath.

## Vie privée

L'agent ne transmet des données **qu'au serveur CACyber du cabinet qui l'a fourni**. Il réalise un audit
de cybersécurité **autorisé par un mandat signé**, en **lecture seule** : aucune exploitation, aucune
intrusion, aucune force brute, aucune modification.

Les observations sont envoyées en HTTPS et chaque requête est signée par une clé propre au poste. Les
identifiants éventuellement saisis par l'entité auditée restent en mémoire : ils ne sont jamais
enregistrés sur le disque ni transmis.

L'agent ne transmet aucune donnée à SignPath ni aux éditeurs des outils.

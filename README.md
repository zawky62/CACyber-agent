# CACyber-Agent

Agent de scan **en lecture seule** installé chez l'entité contrôlée. Un exécutable Windows unique et
statique (`CACCyber-Agent.exe`, Go, bibliothèque standard uniquement, aucun dossier Python livré).

## Architecture : client léger

| Dans l'agent | Sur le serveur (jamais dans l'agent) |
|---|---|
| Appairage (code à usage unique → certificat client) | Règles de détection, rédaction des constats |
| Calcul des cibles autorisées, découverte réseau | Corrélation CVE / CVSS / EPSS / KEV |
| Inventaire local en lecture seule | Score et note A→E, consolidation multi-sites |
| Journal lisible, transmission signée en mTLS | Feuilles de travail, rapports, courriers |

Même décompilé, l'agent ne révèle ni règle ni barème, et ne détient aucun secret partagé : sa seule
clé est **propre au poste**, générée localement, et **révocable** depuis la console d'administration.
La protection repose sur l'architecture, la **signature de code** et le cadre contractuel (mandat).

```
agent/
├── main.go                      options, mode interface / mode console
├── build.bat                    tests + compilation → bin\CACCyber-Agent.exe
└── internal/
    ├── api/        appairage (CSR), client mTLS, requêtes signées
    ├── app/        état de l'agent et actions (relier, lancer, transmettre, changer de code)
    ├── demo/       jeu « Usine de Brest » embarqué (mode --demo)
    ├── etat/       dossier de l'agent : clé, certificat, CA, etat.json, journaux
    ├── journal/    orchestration du scan, étapes, journal lisible, bilan de l'outillage
    ├── outils/     outillage open source : manifeste épinglé, installation, vérification, auto-test
    ├── scan/       cibles, Nmap (liste blanche, profils), scanner natif, inventaire Windows, schéma
    └── ui/         interface locale embarquée (127.0.0.1)
```

## Déroulé

1. **Relier ce site** : le référent saisit le code `CACC-XXXX-XXXX-XXXX-XXXX` remis par le cabinet.
   L'agent génère une clé ECDSA P-256, envoie une CSR à `POST /agent/v1/enrolement` ; le serveur
   vérifie le code (usage unique, non expiré) **et le mandat signé couvrant le site**, puis signe un
   certificat client valable jusqu'à la fin du mandat.
2. **Lancer le scan interne** : sur l'écoute mTLS (certificat client exigé), `POST /agent/v1/scans`
   — le serveur revérifie le mandat. Collecte en lecture seule, journal transmis au fil de l'eau.
3. **Transmettre au dossier** : les observations brutes sont envoyées ; le serveur les analyse et
   renvoie note, score et nombre de constats. Une copie exacte de ce qui a été transmis reste sur le poste.

Chaque requête mTLS porte `X-CAC-Agent`, `X-CAC-Horodatage` et `X-CAC-Signature` =
ECDSA-SHA256 (DER, base64) de `MÉTHODE\nCHEMIN\nHORODATAGE\nsha256(corps)` (anti-rejeu ± 5 min).

## Ce qui est collecté (liste exhaustive)

**Réseau** (plages du mandat, sinon le /24 privé du poste ; jamais d'adresse publique ; 1 024 hôtes max.)
- ports TCP ouverts parmi la liste de la politique (connexion TCP complète) ;
- avec Nmap : service, produit et version (`-sV --version-light`) et les scripts de la **liste
  blanche compilée**, tous de catégorie « safe » : `banner`, `nbstat`, `smb-protocols`,
  `smb2-security-mode`, `smb-os-discovery`, `ftp-anon`, `rdp-enum-encryption`, `ssh2-enum-algos`,
  `http-title`, `http-auth` ;
- sans Nmap : bannières spontanées (SSH, FTP), un `GET /` sans identifiant pour lire si une
  authentification est exigée, une poignée de main TLS par version (1.0 à 1.3).

**Poste qui exécute l'agent** (Windows, commandes PowerShell / système **constantes**)
- système (nom, version, build) ; logiciels installés (clés « Uninstall ») ; correctifs et dates ;
- antivirus (Defender ou Centre de sécurité) : actif, temps réel, âge des signatures ;
- politique de mots de passe et de verrouillage (`net accounts`) ;
- comptes locaux, appartenance au groupe Administrateurs, compte intégré ;
- partages et droit d'écriture accordé à « Tout le monde » ;
- dernière sauvegarde « Sauvegarde Windows Server » (`Get-WBSummary`, équivalent de `wbadmin get versions`) ;
- taille du journal de sécurité, audit des ouvertures de session (`auditpol /get`).

Certaines lectures exigent des droits d'administrateur : à défaut, elles sont notées « non lues »
dans le journal, sans échec du scan.

**Contrôles web passifs** (chaque service web découvert, sauf profil Industriel)
- certificat présenté (expiré, autosigné, nom incorrect, autorité inconnue) ; suites de chiffrement
  faibles acceptées (au plus 6 poignées de main par port) ;
- une requête `GET /` sans redirection : en-têtes de sécurité, technologies annoncées.

**osquery** (poste local, binaire signé par l'éditeur) : requêtes `SELECT` en liste blanche —
BitLocker, centre de sécurité Windows (pare-feu, mises à jour, antivirus, UAC), nombre de programmes.

**Annuaire Active Directory** (si le poste est membre d'un domaine, sauf `collecte_ad = aucune`)
- LDAPS, sinon StartTLS ; jamais en clair ; liaison Kerberos/NTLM (SSPI) sous l'identité Windows
  courante, ou avec le compte saisi par `--identifiants-ad` ;
- comptes, groupes, ordinateurs, appartenances, indicateurs de compte, délégations, politique du
  domaine, présence de LAPS (dates d'expiration seulement), DACL des objets (contrôle `SD_FLAGS`) ;
- **jamais** : mots de passe LAPS, empreintes, demande de ticket de service, écriture.

**Inventaire authentifié** (uniquement si l'entité saisit un compte, uniquement les hôtes du mandat)
- Windows (WinRM HTTPS 5986, NTLM) : un script PowerShell de lecture figé (système, logiciels,
  correctifs, administrateurs locaux, pare-feu, BitLocker, antivirus) ;
- Linux (SSH 22) : cinq commandes de lecture figées ; empreinte de la clé d'hôte relevée,
  `--ssh-known-hosts` pour refuser toute clé inconnue.

## Ce qui n'est JAMAIS fait

Exploitation de faille, test d'intrusion, force brute, essai de mot de passe ou d'identifiant par
défaut, envoi de charge, modification de configuration, lecture de secret de l'annuaire, demande de
ticket Kerberos de service, enregistrement ou transmission d'un identifiant fourni par l'entité, écriture sur un équipement, scan UDP,
script Nmap hors liste blanche, `--script-args`, catégorie de scripts, cible publique.
Le serveur ne peut pas envoyer de commande : il ne fournit qu'une politique bornée, recoupée par la
liste blanche compilée (un serveur compromis ne rend pas l'agent offensif).

## Utilisation

```
CACCyber-Agent.exe                                  interface locale dans le navigateur
CACCyber-Agent.exe --cli --code CACC-…-…-…-…        déroulé complet en console
CACCyber-Agent.exe --demo                           réseau simulé, appairage et envoi réels
```

| Option | Rôle |
|---|---|
| `--serveur URL` | plateforme (défaut `http://localhost:8000`) ; HTTP refusé hors de ce poste sauf `--dev` |
| `--code CODE` | appairage non interactif |
| `--demo` | jeu de démonstration « Usine de Brest » |
| `--cli` | mode console |
| `--nmap CHEMIN` | exécutable Nmap (sinon `Program Files\Nmap`, puis PATH) ; signature de l'éditeur exigée sous Windows |
| `--installer-outils` | installe et vérifie osquery (signé par l'éditeur), exécute l'auto-test, écrit le bilan au journal |
| `--etat-outils` | contrôle l'outillage (empreintes, signatures) sans rien télécharger |
| `--installer-nmap` | télécharge l'installateur officiel de Nmap, le vérifie et l'ouvre en mode interactif (UAC) |
| `--npcap` | ouvre la page officielle de Npcap (option des scans avancés) |
| `--ca FICHIER` | épingle la CA attendue du serveur |
| `--donnees DOSSIER` | dossier de l'agent (défaut `%ProgramData%\CACyber\Agent`) |
| `--reinitialiser` | oublie l'appairage |
| `--domaine-ad NOM` | domaine Active Directory à lire (défaut : celui du poste) |
| `--identifiants-ad` | saisir (sans écho) un compte de domaine pour l'annuaire ; sinon identité Windows courante |
| `--identifiants-windows` | saisir un compte d'administration Windows pour l'inventaire authentifié (WinRM) |
| `--identifiants-linux` | saisir un compte SSH pour l'inventaire des serveurs Linux |
| `--winrm-http` | autoriser WinRM sur HTTP 5985 (NTLM) si HTTPS est indisponible |
| `--winrm-certificat-non-verifie` | accepter un certificat WinRM autosigné (déconseillé) |
| `--ssh-known-hosts FICHIER` | refuser toute clé SSH absente du fichier de l'entité |
| `--version` | version |

L'interface locale écoute sur `127.0.0.1` (port aléatoire) et exige un jeton de session aléatoire ;
l'en-tête Host est contrôlé et les actions n'acceptent que du JSON.

### Dossier de l'agent

| Fichier | Contenu |
|---|---|
| `cle.pem` | clé privée du poste (seul secret ; TODO : protection DPAPI) |
| `certificat.pem` | certificat client émis par la CA de la plateforme |
| `ca.pem` | CA de la plateforme (épinglée pour l'écoute mTLS) |
| `etat.json` | identifiant d'agent, adresses, site, SIRET, client, cabinet |
| `journaux/scan-*.log` | journal lisible de chaque scan, remis au client |
| `journaux/observations-*.json` | copie exacte des observations transmises |

## Compilation

```
build.bat                         (tests puis bin\CACCyber-Agent.exe ; VERSION=1.2.0 build.bat)
```
Équivalent manuel : `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=1.0.0" -o bin/CACCyber-Agent.exe .`
puis `go test ./...`.

## Signature de code (certificat EV)

À réaliser sur le poste de signature (jeton matériel du certificat EV) avant toute diffusion :

```
rem signtool est fourni par le Windows SDK ; /tr = horodatage RFC 3161, indispensable
rem pour que la signature reste valide après l'expiration du certificat.
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /n "Nom exact du titulaire du certificat EV" bin\CACCyber-Agent.exe
signtool verify /pa /v bin\CACCyber-Agent.exe
```

## Outillage open source et Nmap

Voir `docs/NMAP.md` (argumentation, licence NPSL, profils de scan) et `docs/OUTILS.md` (manifeste,
empreintes).

**Nmap**
- Nmap est appelé **en sous-processus** et n'est **pas redistribué**.
- L'agent utilise l'installation présente sur le poste, dont la signature est vérifiée avant chaque
  exécution. Si elle est absente, il propose l'installateur officiel.
- Aucune licence OEM n'est nécessaire.
- Sans Nmap, le scanner natif fournit les ports, les bannières et les versions TLS, mais pas les versions
  SMB négociées.

**osquery** est utilisé depuis son installation officielle (Program Files) si elle est présente et
signée, sinon installé pour l'utilisateur courant, sans droits administrateur, dans
`%LOCALAPPDATA%\CACyber\outils`. Les outils sont lancés sans fenêtre de console. **Seuls des composants
signés par leur éditeur sont exécutés** (Nmap, osquery) ; Nuclei n'est plus utilisé (binaire non
signé, classé « hacktool » par plusieurs EDR) : ses contrôles passifs TLS / en-têtes HTTP sont
intégrés à l'agent. Voir `docs/EDR-LISTE-AUTORISATION.md`.

**Antivirus**
- Une compilation **non signée** de l'agent peut être signalée par un antivirus. C'est arrivé une fois
  avec Defender (« Trojan:Win32/Bearfoos.A!ml », heuristique) sur un binaire de test placé dans un dossier
  temporaire.
- La signature de code (section précédente) est donc indispensable avant toute diffusion.
- Communiquez au service informatique du client les empreintes et l'éditeur de l'agent.

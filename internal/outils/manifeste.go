// Package outils installe, vérifie et décrit l'outillage open source de l'agent (brief §12.2, §14) :
// Nmap, osquery et Nuclei, plus une liste blanche de modèles Nuclei non intrusifs.
//
// Principes de sécurité :
//   - Manifeste VERSIONNÉ et COMPILÉ : version, adresse HTTPS officielle, empreinte SHA-256 de
//     l'archive ET de chaque fichier extrait. Rien n'est téléchargé hors de ce manifeste ; aucune
//     URL, aucun argument ne vient d'une saisie ou du serveur.
//   - Installation par utilisateur, SANS droits administrateur, dans
//     %LOCALAPPDATA%\CACyber\outils\<outil>\<version> (ACL protégée, liens refusés).
//   - Vérification AVANT EXTRACTION (empreinte de l'archive) puis AVANT CHAQUE EXÉCUTION
//     (empreinte du binaire lu au travers d'un descripteur qui interdit toute écriture pendant
//     l'exécution, et signature Authenticode quand l'éditeur signe). Écart = refus d'exécuter.
//   - Nmap n'est PAS redistribué ni téléchargé en archive : depuis la 7.93, l'éditeur ne publie plus
//     d'archive portable Windows, seulement un installateur officiel interactif. L'agent utilise une
//     installation de Nmap signée par l'éditeur ; sinon il propose l'installateur officiel (vérifié,
//     lancé UNIQUEMENT à la demande de l'utilisateur) et, en attendant, se replie sur son scanner natif.
//     Voir docs/NMAP.md.
package outils

// Fichier : un fichier retenu d'une archive (liste blanche : tout autre membre est ignoré).
type Fichier struct {
	Membre string // nom exact dans l'archive (séparateur « / »)
	Dest   string // chemin relatif dans le dossier d'installation
	SHA256 string // empreinte attendue après extraction
	Taille int64  // taille maximale admise (octets)
}

// Outil : composant tiers géré par l'agent.
type Outil struct {
	Nom         string
	Version     string
	Licence     string // identifiant SPDX
	URLSource   string // dépôt des sources (transparence, obligations de licence)
	URL         string // archive officielle (HTTPS)
	SHA256      string // empreinte de l'archive
	TailleMax   int64  // taille maximale de l'archive téléchargée
	Executable  string // binaire principal (relatif au dossier d'installation)
	Fichiers    []Fichier
	Signataires []string // organisations Authenticode admises (vide : binaire non signé par l'éditeur)
	// SourceEmpreinte : d'où vient l'empreinte épinglée (contrôle croisé effectué le 2026-11-06).
	SourceEmpreinte string
}

// Osquery 5.24.1 (Apache-2.0 OU GPL-2.0, au choix) : inventaire local en lecture seule.
// Empreinte de l'archive = « digest » publié par GitHub pour l'actif de la release 5.24.1, recalculée
// localement ; osqueryi.exe est signé Authenticode « OSQUERY a Series of LF Projects, LLC ».
var Osquery = Outil{
	Nom:        "osquery",
	Version:    "5.24.1",
	Licence:    "Apache-2.0 OR GPL-2.0-only",
	URLSource:  "https://github.com/osquery/osquery",
	URL:        "https://github.com/osquery/osquery/releases/download/5.24.1/osquery-5.24.1.windows_x86_64.zip",
	SHA256:     "a71d6d3f57b9fb051988c341fd5186c548fcf83bc94f73cc2cc0a83d702391e9",
	TailleMax:  40 << 20,
	Executable: "osqueryi.exe",
	Fichiers: []Fichier{
		{Membre: "osquery-5.24.1.windows_x86_64/Program Files/osquery/osqueryi.exe", Dest: "osqueryi.exe",
			SHA256: "3df132e4531bfd4e897f5768b272cc0360045c9777cdfc147073e395d2e1d295", Taille: 64 << 20},
		{Membre: "osquery-5.24.1.windows_x86_64/control/LICENSE.txt", Dest: "LICENCE.txt",
			SHA256: "8412c04ff027b7c95c9f9f44b4feb321a0416b1c0124f69637d31d0a0de8df3a", Taille: 64 << 10},
	},
	Signataires:     []string{"OSQUERY a Series of LF Projects, LLC"},
	SourceEmpreinte: "GitHub release asset digest (sha256) osquery/osquery 5.24.1",
}

// Nuclei 3.11.1 (MIT) : détection de mauvaises configurations par modèles sûrs.
// Empreinte de l'archive = fichier nuclei_3.11.1_checksums.txt publié avec la release (identique au
// « digest » GitHub). nuclei.exe n'est PAS signé par l'éditeur : seule l'empreinte fait foi.
var Nuclei = Outil{
	Nom:        "nuclei",
	Version:    "3.11.1",
	Licence:    "MIT",
	URLSource:  "https://github.com/projectdiscovery/nuclei",
	URL:        "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip",
	SHA256:     "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2",
	TailleMax:  80 << 20,
	Executable: "nuclei.exe",
	Fichiers: []Fichier{
		{Membre: "nuclei.exe", Dest: "nuclei.exe",
			SHA256: "73d5e5b0dde9ea5d5fc15dcc34c756148ccae20dc431a21e611af11b8649b480", Taille: 256 << 20},
		{Membre: "LICENSE.md", Dest: "LICENCE.md",
			SHA256: "5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c", Taille: 64 << 10},
	},
	SourceEmpreinte: "nuclei_3.11.1_checksums.txt (release officielle) = digest GitHub",
}

// Geres : outils téléchargés et installés par l'agent (Nmap est traité à part, voir nmap.go).
var Geres = []Outil{Osquery, Nuclei}

// Modele : modèle Nuclei de la liste blanche (fichier unique, empreinte épinglée).
type Modele struct {
	ID     string
	Chemin string // relatif à la racine du dépôt nuclei-templates
	SHA256 string
}

// VersionModeles : étiquette du dépôt projectdiscovery/nuclei-templates (licence MIT).
const VersionModeles = "v10.5.1"

// baseModeles : contenu brut du dépôt à l'étiquette épinglée.
const baseModeles = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/" + VersionModeles + "/"

// ModelesNuclei : LISTE BLANCHE explicite (par identifiant) des modèles exécutables. Uniquement
// des contrôles passifs : négociation TLS (protocole « ssl ») et une requête GET de la page
// d'accueil (en-têtes, technologies). Aucun modèle « intrusive », « dos », « fuzz », « brute »,
// « exploit », aucune charge utile, aucun protocole « code », « javascript » ou « headless ».
// Empreintes : fichiers extraits de l'archive de l'étiquette v10.5.1, dont l'empreinte
// (00184ad4…ac50) figure dans nuclei-templates-10.5.1_checksums.txt publié avec la release, puis
// comparés octet à octet au contenu brut servi par GitHub.
var ModelesNuclei = []Modele{
	{"deprecated-tls", "ssl/deprecated-tls.yaml", "eddb5bd44d68955aab0ef060083271db8ea0fd495bdf50859d5d1d54ea421531"},
	{"expired-ssl", "ssl/expired-ssl.yaml", "23e2fa79491ae665e809b9af4b6636f7b4c21ad7d05c5d54801ecd0c29a16088"},
	{"self-signed-ssl", "ssl/self-signed-ssl.yaml", "bfdadaaa257aba1ba29c095d0d44237a44a2d5ceb4f58cf0993ec1a484af6fc1"},
	{"mismatched-ssl-certificate", "ssl/mismatched-ssl-certificate.yaml", "8946b8e66ea6c2d5f13810f15c321e35a6a1e212cbd07daa8c3882a41f808fa9"},
	{"untrusted-root-certificate", "ssl/untrusted-root-certificate.yaml", "d9d1c176cca2e23233d17fabd56b693630d0c35ad713891d599c2636f095275e"},
	{"weak-cipher-suites", "ssl/weak-cipher-suites.yaml", "956fa0117f123ba9125caec8ff0ad32a1fb76cf879c1bb7d5303570558da66ee"},
	{"tls-version", "ssl/tls-version.yaml", "3a6f237e5df5389726233a1aed71f00252f3f3f5afd486469ce8776b2421b61f"},
	{"http-missing-security-headers", "http/misconfiguration/http-missing-security-headers.yaml", "7f45803f73ac6810b9b302df6be2c472a82d9164a7807328614efa83e6eac275"},
	{"tech-detect", "http/technologies/tech-detect.yaml", "981080e049c7a1c9e418048e41ef7d7089d9f4f1b1c9d3d8094136349c087a95"},
}

// EtiquettesExclues : passées à Nuclei (-etags) en défense en profondeur, même si la liste
// blanche ne contient aucun modèle portant ces étiquettes.
var EtiquettesExclues = []string{"intrusive", "dos", "fuzz", "fuzzing", "brute", "bruteforce", "exploit", "rce",
	"sqli", "xss", "lfi", "ssrf", "oast", "default-login", "takeover"}

// TypesExclus : protocoles Nuclei jamais chargés (-ept).
var TypesExclus = []string{"code", "javascript", "headless", "file", "workflow", "websocket", "whois", "dns"}

// LicenceModeles : texte de licence (MIT) du dépôt de modèles, conservé avec les modèles.
var LicenceModeles = Modele{"licence", "LICENSE.md", "5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c"}

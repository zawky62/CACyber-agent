// Package outils installe, vérifie et décrit l'outillage open source de l'agent (brief §12.2, §14) :
// Nmap et osquery, deux composants SIGNÉS par leur éditeur (Authenticode vérifié avant chaque
// exécution). Nuclei n'est plus utilisé : binaire non signé, classé « hacktool » par plusieurs EDR ;
// ses contrôles passifs (TLS, en-têtes HTTP, technologies) sont réimplémentés nativement dans
// l'agent (paquet scan, fichier web.go).
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

// Geres : outils téléchargés et installés par l'agent (Nmap est traité à part, voir nmap.go).
var Geres = []Outil{Osquery}

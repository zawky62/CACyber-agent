package outils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Nmap (licence NPSL, libre et gratuite) : appelé en PROCESSUS SÉPARÉ, jamais lié ni redistribué.
//
// Depuis la version 7.93, nmap.org ne publie plus d'archive portable pour Windows : seulement
// l'installateur officiel signé (« Nmap Software LLC »), interactif dans son édition gratuite. L'agent :
//  1. utilise l'installation de Nmap présente sur le poste, après contrôle de sa signature ;
//  2. sinon, à la DEMANDE de l'utilisateur, télécharge l'installateur officiel, en vérifie l'empreinte
//     SHA-256 épinglée et la signature, puis le lance en mode interactif (fenêtre UAC de Windows ;
//     l'utilisateur peut décocher Npcap) — jamais d'installation silencieuse ;
//  3. en attendant ou en cas de refus, se replie sur son scanner natif (connexions TCP).
//
// Le scan reste en mode « connect » (-sT, --unprivileged) : ni Npcap ni droits administrateur requis.

// NmapInstallateur : installateur officiel épinglé.
// Empreinte : nmap.org/dist/sigs/nmap-7.993-setup.exe.digest.txt, recalculée localement ; signature
// GPG du fichier vérifiée (« Good signature », clé « Nmap Project Signing Key »
// 436D 66AB 9A79 8425 FDA0 E3F8 01AF 9F03 6B93 55D0, empreinte publiée dans le guide officiel) ;
// signature Authenticode valide « Nmap Software LLC ».
var NmapInstallateur = Outil{
	Nom:             "nmap",
	Version:         "7.993",
	Licence:         "NPSL (Nmap Public Source License)",
	URLSource:       "https://nmap.org/dist/nmap-7.993.tar.bz2",
	URL:             "https://nmap.org/dist/nmap-7.993-setup.exe",
	SHA256:          "22e5928d1738a1b94ffd3643014f52cb87d467dbec4cff9e5f721fe0b3782f1b",
	TailleMax:       64 << 20,
	Signataires:     SignatairesNmap,
	SourceEmpreinte: "nmap.org digest.txt + signature GPG (clé 6B9355D0) + Authenticode",
}

// SignatairesNmap : éditeurs Authenticode admis pour nmap.exe (« Insecure.Com LLC » pour les
// versions antérieures, « Nmap Software LLC » pour les versions récentes).
var SignatairesNmap = []string{"Nmap Software LLC", "Insecure.Com LLC"}

// EmplacementsNmap : installations standard de l'installateur officiel (dossiers protégés,
// modifiables par les seuls administrateurs).
func EmplacementsNmap() []string {
	var res []string
	if runtime.GOOS == "windows" {
		for _, v := range []string{"ProgramFiles(x86)", "ProgramFiles"} {
			if b := os.Getenv(v); b != "" {
				res = append(res, filepath.Join(b, "Nmap", "nmap.exe"))
			}
		}
	}
	return res
}

// PreparerNmap renvoie un Nmap VÉRIFIÉ, prêt à l'exécution (à fermer après usage).
//   - `explicite` (option --nmap) : ce binaire seul, avec le même contrôle de signature sous Windows ;
//   - sinon : emplacements standard, puis PATH.
//
// Sous Windows, un nmap.exe dont la signature n'est pas valide ou n'émane pas de l'éditeur est
// REFUSÉ. Ailleurs, le binaire du système (paquet de la distribution) est utilisé tel quel.
func PreparerNmap(explicite string) (*Executable, error) {
	var candidats []string
	if explicite != "" {
		candidats = []string{explicite}
	} else {
		candidats = EmplacementsNmap()
		if p, err := exec.LookPath("nmap"); err == nil {
			candidats = append(candidats, p)
		}
	}
	o := Outil{Nom: "nmap", Licence: NmapInstallateur.Licence, URL: "installation du poste"}
	if runtime.GOOS == "windows" {
		o.Signataires = SignatairesNmap
	}
	var derniere error = errors.New("Nmap n'est pas installé sur ce poste")
	for _, c := range candidats {
		if st, err := os.Stat(c); err != nil || st.IsDir() {
			continue
		}
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		x, err := preparerChemin(o, abs, "")
		if err != nil {
			derniere = err
			continue
		}
		return x, nil
	}
	return nil, derniere
}

// PreparerInstallateurNmap télécharge l'installateur officiel dans le dossier géré, en vérifie
// l'empreinte (au téléchargement) puis la signature Authenticode. Rien n'est exécuté.
func (g *Gestionnaire) PreparerInstallateurNmap(ctx context.Context) (string, error) {
	g.Progres(Etape{"nmap", "Téléchargement de l'installateur officiel de Nmap " + NmapInstallateur.Version + " (nmap.org)…", 0})
	tmp, err := g.telecharger(ctx, "nmap-setup", NmapInstallateur.URL, NmapInstallateur.SHA256, NmapInstallateur.TailleMax)
	if err != nil {
		return "", err
	}
	cible := filepath.Join(g.Racine, ".telechargements", "nmap-"+NmapInstallateur.Version+"-setup.exe")
	_ = os.Remove(cible)
	if err := os.Rename(tmp, cible); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	x, err := preparerChemin(NmapInstallateur, cible, NmapInstallateur.SHA256)
	if err != nil {
		_ = os.Remove(cible)
		return "", err
	}
	x.Fermer()
	g.Progres(Etape{"nmap", fmt.Sprintf("Installateur vérifié : SHA-256 conforme, signé « %s ».", x.Signataire), 100})
	return cible, nil
}

// LancerInstallateurNmap ouvre l'installateur officiel VÉRIFIÉ en mode interactif. Appelé
// uniquement sur action explicite de l'utilisateur ; l'élévation (UAC) est demandée par Windows et
// peut être refusée sans conséquence (l'agent reste sur son scanner natif).
func LancerInstallateurNmap(chemin string) error {
	x, err := preparerChemin(NmapInstallateur, chemin, NmapInstallateur.SHA256)
	if err != nil {
		return err
	}
	// Le verrou est relâché juste avant le lancement : l'installateur est sous ACL protégée et
	// Windows revérifie sa signature au moment de l'élévation (fenêtre UAC « éditeur vérifié »).
	x.Fermer()
	return lancerInstallateur(chemin)
}

// AdresseNpcap : page officielle de téléchargement de Npcap (édition gratuite). Npcap n'est
// JAMAIS embarqué ni installé silencieusement : il n'est utile qu'aux scans avancés (SYN, OS).
const AdresseNpcap = "https://npcap.com/#download"

// OuvrirPageNpcap ouvre la page officielle de Npcap dans le navigateur, sur demande de l'utilisateur.
func OuvrirPageNpcap() error { return ouvrirAdresse(AdresseNpcap) }

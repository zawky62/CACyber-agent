package scan

import (
	"fmt"
	"sort"
)

// ListeBlancheNSE est la liste COMPILÉE des scripts Nmap que l'agent accepte d'exécuter.
// Tous appartiennent à la catégorie « safe » de Nmap : ils lisent des bannières, négocient
// des protocoles ou consultent des en-têtes, sans exploitation ni essai de mot de passe.
//
// Le serveur envoie sa propre liste (politique.scripts_nse) : l'agent n'exécute que
// l'INTERSECTION des deux. Ainsi, même un serveur compromis ne peut pas transformer l'agent
// en outil offensif : aucun script hors de cette liste ne sera jamais lancé.
var ListeBlancheNSE = map[string]bool{
	"banner":              true,
	"nbstat":              true,
	"smb-protocols":       true,
	"smb2-security-mode":  true,
	"smb-os-discovery":    true,
	"ftp-anon":            true,
	"rdp-enum-encryption": true,
	"ssh2-enum-algos":     true,
	"http-title":          true,
	"http-auth":           true,
}

// Politique : paramètres bornés reçus du serveur (jamais une commande à exécuter).
type Politique struct {
	ScriptsNSE       []string `json:"scripts_nse"`
	Ports            []int    `json:"ports"`
	Timing           string   `json:"timing"`
	MaxHotes         int      `json:"max_hotes"`
	PlagesAutorisees []string `json:"plages_autorisees"`
	LectureSeule     bool     `json:"lecture_seule"`
	NmapVersionMin   string   `json:"nmap_version_min"`
}

// ScriptsAutorises renvoie l'intersection triée entre la demande du serveur et la liste
// blanche compilée, ainsi que les scripts refusés (journalisés comme tels).
func ScriptsAutorises(demandes []string) (autorises, refuses []string) {
	vus := map[string]bool{}
	for _, s := range demandes {
		if vus[s] {
			continue
		}
		vus[s] = true
		if ListeBlancheNSE[s] {
			autorises = append(autorises, s)
		} else {
			refuses = append(refuses, s)
		}
	}
	sort.Strings(autorises)
	sort.Strings(refuses)
	return
}

// PortsValides filtre les ports reçus (1..65535, dédoublonnés). Si la liste est vide,
// une liste par défaut identique à celle du serveur est utilisée.
func PortsValides(ports []int) []int {
	if len(ports) == 0 {
		ports = []int{21, 22, 23, 53, 80, 88, 102, 135, 139, 161, 389, 443, 445, 502, 515, 1433, 3306, 3389,
			5000, 5001, 5900, 8080, 8443, 9100, 47808}
	}
	vus := map[int]bool{}
	var res []int
	for _, p := range ports {
		if p >= 1 && p <= 65535 && !vus[p] {
			vus[p] = true
			res = append(res, p)
		}
	}
	sort.Ints(res)
	return res
}

// Timing valide le gabarit de temporisation Nmap : seuls T2 (lent) et T3 (normal) sont
// acceptés, pour ne jamais surcharger le réseau de l'entité.
func Timing(t string) string {
	if t == "T2" {
		return "T2"
	}
	return "T3"
}

// VerifierLectureSeule refuse de démarrer si le serveur ne confirme pas le mode lecture seule.
func (p Politique) VerifierLectureSeule() error {
	if !p.LectureSeule {
		return fmt.Errorf("la politique reçue ne confirme pas le mode lecture seule : scan refusé")
	}
	return nil
}

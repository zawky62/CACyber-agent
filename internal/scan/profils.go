package scan

import (
	"sort"
	"strconv"
	"strings"
)

// Profils de scan (brief §13, §15.4) : jeux d'options FIGÉS dans le code. Le serveur choisit un
// profil par son NOM (énumération) ; il ne transmet jamais d'option Nmap. Un nom inconnu retombe
// sur « standard ». Tous les profils sont en mode « connect » (-sT, --unprivileged) : ni Npcap ni
// droits administrateur, aucune détection d'OS active, aucun script hors liste blanche.

// Profil : nom d'un profil de scan.
type Profil string

// Profils disponibles.
const (
	ProfilDecouverte Profil = "decouverte" // cartographie rapide : qui est là, quels services courants
	ProfilStandard   Profil = "standard"   // audit courant : services + versions + scripts « safe »
	ProfilApprofondi Profil = "approfondi" // plus de ports, détection de versions plus poussée
	ProfilIndustriel Profil = "industriel" // réseaux fragiles (OT, automates) : très lent, sans sondes de version
)

// ParametresProfil : réglages d'un profil.
type ParametresProfil struct {
	Nom              Profil
	Libelle          string
	Timing           string // gabarit maximal (T2 lent, T3 normal) ; jamais plus rapide
	DetectionVersion bool   // -sV
	IntensiteVersion int    // 0..9 (2 = --version-light)
	Scripts          bool   // scripts NSE de la liste blanche autorisés
	MaxRetries       int
	HostTimeout      string
	ScanDelay        string // délai minimal entre sondes vers un même hôte (vide : aucun)
	MaxRate          int    // paquets/s maximum (0 : non borné par le profil)
	MaxParallelisme  int    // sondes simultanées maximum (0 : défaut Nmap)
	PortsDecouverte  []int  // découverte d'hôtes par connexion TCP (-PS, mode non privilégié)
	PortsSupp        []int  // ports ajoutés à la liste du serveur
	PortsMax         []int  // si non vide : seuls ces ports peuvent être examinés
	ExclureFragiles  bool   // ports d'équipements fragiles exclus sauf accord explicite (mandat)
}

// PortsFragiles : protocoles d'automates, de supervision industrielle et d'impression, connus pour
// réagir mal à des sondes (redémarrage d'automate, impression de pages parasites…).
var PortsFragiles = []int{102, 502, 789, 1911, 2404, 4911, 5007, 9100, 9101, 9102, 9600, 18245, 20000, 44818, 47808}

var decouverteStandard = []int{22, 80, 135, 139, 443, 445, 3389}

var profils = map[Profil]ParametresProfil{
	ProfilDecouverte: {Nom: ProfilDecouverte, Libelle: "Découverte", Timing: "T3", DetectionVersion: true, IntensiteVersion: 0,
		MaxRetries: 1, HostTimeout: "3m", PortsDecouverte: decouverteStandard,
		PortsMax: []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443}},
	ProfilStandard: {Nom: ProfilStandard, Libelle: "Standard", Timing: "T3", DetectionVersion: true, IntensiteVersion: 2,
		Scripts: true, MaxRetries: 1, HostTimeout: "5m", PortsDecouverte: decouverteStandard},
	ProfilApprofondi: {Nom: ProfilApprofondi, Libelle: "Approfondi", Timing: "T3", DetectionVersion: true, IntensiteVersion: 7,
		Scripts: true, MaxRetries: 2, HostTimeout: "15m", PortsDecouverte: decouverteStandard,
		PortsSupp: []int{25, 110, 111, 143, 389, 465, 587, 636, 873, 993, 995, 1521, 2049, 2375, 3000, 5432, 5985, 5986,
			6379, 8000, 8081, 8888, 9000, 9200, 10000, 11211, 27017}},
	ProfilIndustriel: {Nom: ProfilIndustriel, Libelle: "Industriel (très prudent)", Timing: "T2", DetectionVersion: false,
		MaxRetries: 0, HostTimeout: "10m", ScanDelay: "500ms", MaxRate: 5, MaxParallelisme: 1,
		PortsDecouverte: []int{80, 443}, ExclureFragiles: true},
}

// ProfilDepuis convertit le nom reçu du serveur ; `false` si le nom est inconnu (repli : standard).
func ProfilDepuis(nom string) (ParametresProfil, bool) {
	if nom == "" {
		return profils[ProfilStandard], true
	}
	p, ok := profils[Profil(strings.ToLower(strings.TrimSpace(nom)))]
	if !ok {
		return profils[ProfilStandard], false
	}
	return p, true
}

// Profils renvoie les profils triés (documentation, interface).
func Profils() []ParametresProfil {
	res := make([]ParametresProfil, 0, len(profils))
	for _, p := range profils {
		res = append(res, p)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Nom < res[j].Nom })
	return res
}

// Ports renvoie les ports à examiner pour ce profil, à partir de la liste (validée) du serveur.
// `inclureFragiles` ne vaut que si le mandat l'autorise explicitement.
func (p ParametresProfil) Ports(serveur []int, inclureFragiles bool) []int {
	base := PortsValides(append(PortsValides(serveur), p.PortsSupp...)) // liste par défaut si le serveur n'en fournit pas
	if len(p.PortsMax) > 0 {
		autorise := map[int]bool{}
		for _, x := range p.PortsMax {
			autorise[x] = true
		}
		var r []int
		for _, x := range base {
			if autorise[x] {
				r = append(r, x)
			}
		}
		base = r
	}
	if p.ExclureFragiles && !inclureFragiles {
		fragile := map[int]bool{}
		for _, x := range PortsFragiles {
			fragile[x] = true
		}
		var r []int
		for _, x := range base {
			if !fragile[x] {
				r = append(r, x)
			}
		}
		base = r
	}
	return base
}

// TimingProfil : le gabarit du serveur ne peut que RALENTIR celui du profil.
func (p ParametresProfil) TimingProfil(serveur string) string {
	if p.Timing == "T2" || Timing(serveur) == "T2" {
		return "T2"
	}
	return "T3"
}

func joindre(ports []int) string {
	s := make([]string, len(ports))
	for i, x := range ports {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ",")
}

// Package scan regroupe la collecte en LECTURE SEULE réalisée par l'agent CACyber :
// calcul des cibles autorisées, découverte réseau (Nmap en liste blanche ou scanner natif),
// inventaire local du poste et assemblage des observations brutes.
//
// Principe « client léger » : l'agent ne contient AUCUNE règle de détection, aucun score,
// aucune donnée CVE. Il transmet des faits ; toute l'analyse est faite par le serveur.
//
// Les structures ci-dessous reproduisent exactement le schéma accepté par le serveur
// (backend/app/engine/observations.py). Les champs facultatifs sont des pointeurs avec
// `omitempty` : « non collecté » est distinct de « faux ».
package scan

// Port décrit un port ouvert sur un hôte et ce que l'on sait du service qui l'écoute.
type Port struct {
	Port            int      `json:"port"`
	Proto           string   `json:"proto,omitempty"` // "tcp" (défaut) ou "udp"
	Service         string   `json:"service,omitempty"`
	Produit         string   `json:"produit,omitempty"`
	Version         string   `json:"version,omitempty"`
	TLS             []string `json:"tls,omitempty"`               // versions TLS acceptées (ex. "TLSv1.2")
	HTTPAuthRequise *bool    `json:"http_auth_requise,omitempty"` // l'interface HTTP exige-t-elle une authentification ?
}

// SystemeExploitation : nom / version / build tels que détectés.
type SystemeExploitation struct {
	Nom     string `json:"nom,omitempty"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
}

// Smb : dialectes négociés et exigence de signature (lus, jamais modifiés).
type Smb struct {
	Dialectes        []string `json:"dialectes,omitempty"`
	SignatureRequise *bool    `json:"signature_requise,omitempty"`
}

// Logiciel installé (lu dans les clés « Uninstall » du registre).
type Logiciel struct {
	Nom     string `json:"nom"`
	Version string `json:"version,omitempty"`
	Editeur string `json:"editeur,omitempty"`
}

// Correctif (KB) installé, avec sa date d'installation au format AAAA-MM-JJ.
type Correctif struct {
	KB         string  `json:"kb"`
	InstalleLe *string `json:"installe_le,omitempty"`
}

// Antivirus : état lu (présence, protection temps réel, âge des signatures).
type Antivirus struct {
	Produit            string `json:"produit,omitempty"`
	Actif              bool   `json:"actif"`
	TempsReel          *bool  `json:"temps_reel,omitempty"`
	SignaturesAgeJours *int   `json:"signatures_age_jours,omitempty"`
}

// PolitiqueMdp : politique de mots de passe et de verrouillage (lecture de « net accounts »).
type PolitiqueMdp struct {
	LongueurMin       *int `json:"longueur_min,omitempty"`
	ExpirationJours   *int `json:"expiration_jours,omitempty"`
	SeuilVerrouillage *int `json:"seuil_verrouillage,omitempty"`
}

// Partage réseau du poste et indicateur d'écriture ouverte à « Tout le monde ».
type Partage struct {
	Nom                 string `json:"nom"`
	Chemin              string `json:"chemin,omitempty"`
	EcritureToutLeMonde bool   `json:"ecriture_tout_le_monde"`
}

// Compte local (nom, actif, membre des administrateurs, compte intégré RID 500).
type Compte struct {
	Nom     string `json:"nom"`
	Actif   bool   `json:"actif"`
	Admin   bool   `json:"admin"`
	Integre bool   `json:"integre"`
}

// Sauvegardes : dernière sauvegarde connue de l'outil système. Externalisation et test de
// restauration sont DÉCLARATIFS (renseignés côté console), jamais devinés par l'agent.
type Sauvegardes struct {
	Outil                   string  `json:"outil,omitempty"`
	Derniere                *string `json:"derniere,omitempty"`
	NbVersions              *int    `json:"nb_versions,omitempty"`
	Externalisee            *bool   `json:"externalisee,omitempty"`
	DernierTestRestauration *string `json:"dernier_test_restauration,omitempty"`
}

// Journalisation : taille du journal de sécurité et audit des ouvertures de session.
type Journalisation struct {
	TailleMaxMo     *int  `json:"taille_max_mo,omitempty"`
	AuditConnexions *bool `json:"audit_connexions,omitempty"`
}

// Inventaire local du poste qui exécute l'agent.
type Inventaire struct {
	Logiciels      []Logiciel      `json:"logiciels,omitempty"`
	Correctifs     []Correctif     `json:"correctifs,omitempty"`
	Antivirus      *Antivirus      `json:"antivirus,omitempty"`
	PolitiqueMdp   *PolitiqueMdp   `json:"politique_mdp,omitempty"`
	Partages       []Partage       `json:"partages,omitempty"`
	Comptes        []Compte        `json:"comptes,omitempty"`
	Sauvegardes    *Sauvegardes    `json:"sauvegardes,omitempty"`
	Journalisation *Journalisation `json:"journalisation,omitempty"`
}

// Hote : un équipement découvert sur le réseau autorisé.
type Hote struct {
	IP         string               `json:"ip"`
	Nom        string               `json:"nom,omitempty"`
	Type       string               `json:"type,omitempty"`
	Fabricant  string               `json:"fabricant,omitempty"`
	OS         *SystemeExploitation `json:"os,omitempty"`
	Ports      []Port               `json:"ports,omitempty"`
	Smb        *Smb                 `json:"smb,omitempty"`
	FtpAnonyme *bool                `json:"ftp_anonyme,omitempty"`
	RdpNla     *bool                `json:"rdp_nla,omitempty"`
	Inventaire *Inventaire          `json:"inventaire,omitempty"`
}

// Observations : charge utile complète transmise au serveur en fin de scan.
type Observations struct {
	VersionAgent string         `json:"version_agent"`
	Mode         string         `json:"mode"` // "reel" ou "demo"
	Debut        string         `json:"debut,omitempty"`
	Fin          string         `json:"fin,omitempty"`
	Reseaux      []string       `json:"reseaux"`
	Hotes        []Hote         `json:"hotes"`
	Nmap         map[string]any `json:"nmap,omitempty"` // traçabilité : version, arguments, scripts
}

// Limites du schéma serveur : vérifiées AVANT l'envoi pour échouer proprement côté agent.
const (
	MaxHotes      = 4096
	MaxPorts      = 1000
	MaxLogiciels  = 5000
	MaxCorrectifs = 5000
	MaxPartages   = 500
	MaxComptes    = 2000
	MaxReseaux    = 64
	MaxCourt      = 200
)

func tronquer(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// Borner applique les limites du schéma (troncature des listes et des chaînes) et renvoie
// la liste des ajustements effectués, pour qu'ils apparaissent dans le journal.
func (o *Observations) Borner() []string {
	var notes []string
	if len(o.Reseaux) > MaxReseaux {
		o.Reseaux = o.Reseaux[:MaxReseaux]
		notes = append(notes, "liste des réseaux tronquée")
	}
	if len(o.Hotes) > MaxHotes {
		o.Hotes = o.Hotes[:MaxHotes]
		notes = append(notes, "liste des hôtes tronquée")
	}
	for i := range o.Hotes {
		h := &o.Hotes[i]
		h.Nom, h.Type, h.Fabricant = tronquer(h.Nom, MaxCourt), tronquer(h.Type, MaxCourt), tronquer(h.Fabricant, MaxCourt)
		if len(h.Ports) > MaxPorts {
			h.Ports = h.Ports[:MaxPorts]
		}
		for j := range h.Ports {
			p := &h.Ports[j]
			p.Service, p.Produit, p.Version = tronquer(p.Service, MaxCourt), tronquer(p.Produit, MaxCourt), tronquer(p.Version, MaxCourt)
		}
		if inv := h.Inventaire; inv != nil {
			if len(inv.Logiciels) > MaxLogiciels {
				inv.Logiciels = inv.Logiciels[:MaxLogiciels]
				notes = append(notes, "inventaire logiciel tronqué")
			}
			for k := range inv.Logiciels {
				l := &inv.Logiciels[k]
				l.Nom, l.Version, l.Editeur = tronquer(l.Nom, MaxCourt), tronquer(l.Version, MaxCourt), tronquer(l.Editeur, MaxCourt)
			}
			if len(inv.Correctifs) > MaxCorrectifs {
				inv.Correctifs = inv.Correctifs[:MaxCorrectifs]
			}
			for k := range inv.Correctifs {
				inv.Correctifs[k].KB = tronquer(inv.Correctifs[k].KB, 20)
			}
			if len(inv.Partages) > MaxPartages {
				inv.Partages = inv.Partages[:MaxPartages]
			}
			if len(inv.Comptes) > MaxComptes {
				inv.Comptes = inv.Comptes[:MaxComptes]
			}
			for k := range inv.Comptes {
				inv.Comptes[k].Nom = tronquer(inv.Comptes[k].Nom, 120)
			}
		}
	}
	return notes
}

// Compter renvoie le nombre de machines et de ports ouverts (tuiles de l'interface).
func (o *Observations) Compter() (machines, ports int) {
	for _, h := range o.Hotes {
		machines++
		ports += len(h.Ports)
	}
	return
}

// Package scan regroupe la collecte en LECTURE SEULE réalisée par l'agent CACyber :
// calcul des cibles autorisées, découverte réseau (Nmap en liste blanche ou scanner natif),
// inventaire local du poste et assemblage des observations brutes.
//
// Principe « client léger » : l'agent ne contient AUCUNE règle de détection, aucun score,
// aucune donnée CVE. Il transmet des faits ; toute l'analyse est faite par le serveur.
//
// Les structures ci-dessous reproduisent exactement le schéma accepté par le serveur
// (supabase/functions/_shared/moteur/observations.ts). Les champs facultatifs sont des pointeurs avec
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

	// Sections FACULTATIVES (absentes = non collecté ; un serveur plus ancien les ignore).
	Web            []ControleWeb        `json:"web,omitempty"`             // contrôles passifs TLS / en-têtes (web.go)
	AD             *Annuaire            `json:"ad,omitempty"`              // annuaire Active Directory (lecture LDAP)
	InventaireAuth []InventaireAuthHote `json:"inventaire_auth,omitempty"` // inventaire authentifié WinRM / SSH
	Osquery        *Osquery             `json:"osquery,omitempty"`         // compléments osquery du poste local
}

// ----------------------------------------------------------------------------- annuaire AD

// Annuaire : faits collectés en LECTURE SEULE par LDAP (aucune écriture, aucun mot de passe ni secret
// lu : les attributs de mots de passe LAPS sont explicitement exclus). Le graphe (nœuds + arêtes de
// contrôle) permet au SERVEUR de rechercher les chemins d'élévation de privilèges ; l'agent n'en tire
// aucune conclusion (client léger).
type Annuaire struct {
	Domaine       DomaineAD       `json:"domaine"`
	PolitiqueMdp  *PolitiqueMdpAD `json:"politique_mdp,omitempty"`
	QuotaMachines *int            `json:"quota_machines,omitempty"` // ms-DS-MachineAccountQuota
	LAPS          *LapsAD         `json:"laps,omitempty"`
	Noeuds        []NoeudAD       `json:"noeuds"`
	// Aretes : [source, type, cible] (SID), ex. ["S-1-5-21-…-1104", "GenericAll", "S-1-5-21-…-512"].
	Aretes  [][3]string `json:"aretes"`
	Tronque bool        `json:"tronque"`
	Lien    string      `json:"lien"`     // "ldaps" ou "starttls" (toujours chiffré)
	Collecte string     `json:"collecte"` // "ldap" (collecteur natif de l'agent)
}

// DomaineAD : identité du domaine.
type DomaineAD struct {
	Nom               string   `json:"nom"`
	SID               string   `json:"sid"`
	NiveauFonctionnel *int     `json:"niveau_fonctionnel,omitempty"`
	Controleurs       []string `json:"controleurs,omitempty"`
}

// PolitiqueMdpAD : politique de mots de passe du domaine (objet domaine).
type PolitiqueMdpAD struct {
	LongueurMin       *int  `json:"longueur_min,omitempty"`
	Historique        *int  `json:"historique,omitempty"`
	AgeMaxJours       *int  `json:"age_max_jours,omitempty"` // 0 = sans expiration
	SeuilVerrouillage *int  `json:"seuil_verrouillage,omitempty"`
	Complexite        *bool `json:"complexite,omitempty"`
}

// LapsAD : présence de LAPS (schéma) et ordinateurs dont la date d'expiration LAPS est renseignée.
type LapsAD struct {
	SchemaLegacy        bool `json:"schema_legacy"`  // ms-Mcs-AdmPwdExpirationTime
	SchemaWindows       bool `json:"schema_windows"` // msLAPS-PasswordExpirationTime
	OrdinateursCouverts int  `json:"ordinateurs_couverts"`
	OrdinateursTotal    int  `json:"ordinateurs_total"`
}

// NoeudAD : principal de l'annuaire. T = "u" (utilisateur), "g" (groupe), "c" (ordinateur), "d" (domaine).
type NoeudAD struct {
	ID                string  `json:"id"` // SID
	T                 string  `json:"t"`
	N                 string  `json:"n"` // sAMAccountName (u, g) ou nom DNS (c)
	Actif             *bool   `json:"actif,omitempty"`
	AdminCount        bool    `json:"admincount,omitempty"`
	SPN               bool    `json:"spn,omitempty"`                 // compte utilisateur porteur d'un SPN (signalé, jamais sollicité)
	ASREP             bool    `json:"asrep,omitempty"`               // pré-authentification Kerberos non requise (indicateur seul)
	MdpSansExpiration bool    `json:"mdp_sans_expiration,omitempty"` // DONT_EXPIRE_PASSWORD
	DelegNC           bool    `json:"deleg_nc,omitempty"`            // délégation non contrainte
	DC                bool    `json:"dc,omitempty"`                  // contrôleur de domaine
	DerniereConnexion *string `json:"derniere_connexion,omitempty"`  // AAAA-MM-JJ (lastLogonTimestamp)
	MdpChange         *string `json:"mdp_change,omitempty"`          // AAAA-MM-JJ (pwdLastSet)
	OS                string  `json:"os,omitempty"`
}

// Types d'arêtes de contrôle transmis (liste fermée, vérifiée aussi par le serveur).
var TypesAretesAD = []string{"MemberOf", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
	"AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf", "AddKeyCredentialLink", "DCSync",
	"AllowedToDelegate", "AllowedToAct"}

// Limites de l'annuaire transmis (au-delà : troncature signalée).
const (
	MaxNoeudsAD = 30000
	MaxAretesAD = 150000
)

// ----------------------------------------------------------------------------- inventaire authentifié

// InventaireAuthHote : bilan de l'inventaire authentifié d'un hôte. Les données (logiciels, correctifs,
// système) sont fusionnées dans Hote.Inventaire / Hote.OS pour être analysées comme celles du poste.
type InventaireAuthHote struct {
	IP         string `json:"ip"`
	Methode    string `json:"methode"` // "winrm" ou "ssh"
	OK         bool   `json:"ok"`
	Erreur     string `json:"erreur,omitempty"`
	Logiciels  int    `json:"logiciels"`
	Correctifs int    `json:"correctifs"`
	// Compléments Linux / Windows lus en lecture seule.
	SSHRacineAutorisee *bool `json:"ssh_racine_autorisee,omitempty"` // PermitRootLogin yes
	SSHMotDePasse      *bool `json:"ssh_mot_de_passe,omitempty"`     // PasswordAuthentication yes
	PareFeuActif       *bool `json:"pare_feu_actif,omitempty"`
	ChiffrementDisque  *bool `json:"chiffrement_disque,omitempty"` // BitLocker (volume système)
	EmpreinteCleHote   string `json:"empreinte_cle_hote,omitempty"` // SSH : SHA256:… (traçabilité)
}

// ----------------------------------------------------------------------------- osquery (poste local)

// Osquery : compléments lus par osquery (requêtes en lecture seule) sur le poste qui exécute l'agent.
type Osquery struct {
	Version   string            `json:"version"`
	BitLocker []VolumeBitLocker `json:"bitlocker,omitempty"`
	// Centre de sécurité Windows : état déclaré ("Good", "Poor", "Snoozed", "Not Monitored"…).
	PareFeu         string `json:"pare_feu,omitempty"`
	MisesAJour      string `json:"mises_a_jour,omitempty"`
	Antivirus       string `json:"antivirus,omitempty"`
	ControleCompte  string `json:"controle_compte,omitempty"` // UAC
	NbProgrammes    int    `json:"nb_programmes"`
}

// VolumeBitLocker : état de chiffrement d'un volume.
type VolumeBitLocker struct {
	Lecteur    string `json:"lecteur"`
	Protection bool   `json:"protection"` // protection_status = 1
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

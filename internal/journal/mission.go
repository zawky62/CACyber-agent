// Package journal orchestre une mission de scan : étapes, journal lisible (affiché, envoyé au
// serveur et écrit sur le poste), collecte puis transmission. Il est partagé par le mode console
// (--cli) et par l'interface locale.
package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cacyber/agent/internal/annuaire"
	"cacyber/agent/internal/api"
	"cacyber/agent/internal/demo"
	"cacyber/agent/internal/outils"
	"cacyber/agent/internal/scan"
)

// Etapes : libellés affichés pendant le scan (repris du prototype, rendus exacts : l'agent
// collecte, l'analyse des vulnérabilités et la note sont calculées par le serveur).
var Etapes = []string{
	"Connexion au serveur et contrôle du mandat…",
	"Découverte du réseau…",
	"Analyse des ports et services…",
	"Inventaire des logiciels…",
	"Contrôle des correctifs de sécurité…",
	"Relevé des configurations…",
	"Contrôle des sauvegardes et des accès…",
	"Transmission et calcul de la note cyber…",
}

// Statuts de la mission.
const (
	StatutPret     = "pret"     // relié, aucun scan en cours
	StatutScan     = "scan"     // collecte en cours
	StatutCollecte = "collecte" // collecte terminée, prête à transmettre
	StatutTransmis = "transmis" // résultats transmis, note reçue
	StatutErreur   = "erreur"
)

// Ligne du journal.
type Ligne struct {
	Heure string `json:"heure"`
	Type  string `json:"type"` // info | constat | critique | ok | erreur
	Texte string `json:"texte"`
}

// Instantane : état exposé à l'interface (copie sans verrou).
type Instantane struct {
	Statut      string  `json:"statut"`
	Etape       string  `json:"etape"`
	Progression int     `json:"progression"`
	Machines    int     `json:"machines"`
	Ports       int     `json:"ports"`
	Constats    *int    `json:"constats"`
	Note        string  `json:"note"`
	Score       *int    `json:"score"`
	Message     string  `json:"message"`
	Journal     []Ligne `json:"journal"`
	Mode        string  `json:"mode"`
	// Annuaire : résumé « façon BloodHound » renvoyé par le serveur (nil sans données Active Directory).
	Annuaire *api.ResumeAnnuaire `json:"annuaire,omitempty"`
	// ExportBloodHound : chemin de l'archive BloodHound CE produite par l'agent ("" si aucune).
	ExportBloodHound string `json:"export_bloodhound,omitempty"`
}

// Mission : un scan (collecte + transmission) pour le site relié.
type Mission struct {
	mu        sync.Mutex
	client    *api.Client
	demo      bool
	nmap      string
	version   string
	dossierJx string

	// complements : paramètres des collectes complémentaires (identifiants en mémoire).
	complements Complements

	etat    Instantane
	scanID  string
	obs     *scan.Observations
	fichier *os.File
	occupe  bool
	// profilLocal : profil choisi sur le poste (interface) ; vide = profil indiqué par le serveur.
	profilLocal string
}

// Nouvelle prépare une mission ; `dossierJournaux` reçoit le journal lisible et la copie des
// observations transmises (transparence vis-à-vis de l'entité contrôlée).
func Nouvelle(client *api.Client, demo bool, nmap, version, dossierJournaux string) *Mission {
	m := &Mission{client: client, demo: demo, nmap: nmap, version: version, dossierJx: dossierJournaux}
	m.etat = Instantane{Statut: StatutPret, Etape: "Prêt à lancer le scan.", Mode: map[bool]string{true: "demo", false: "reel"}[demo]}
	return m
}

// Etat renvoie une copie de l'état courant.
func (m *Mission) Etat() Instantane {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.etat
	e.Journal = append([]Ligne(nil), m.etat.Journal...)
	return e
}

// log ajoute une ligne au journal : écran, fichier local et serveur (si un scan est ouvert).
func (m *Mission) log(etape int, typ, texte string, progression int) {
	m.mu.Lock()
	l := Ligne{Heure: time.Now().Format("15:04:05"), Type: typ, Texte: texte}
	m.etat.Journal = append(m.etat.Journal, l)
	if etape >= 0 && etape < len(Etapes) {
		m.etat.Etape = Etapes[etape]
	}
	if progression >= 0 {
		m.etat.Progression = progression
	}
	if m.fichier != nil {
		fmt.Fprintf(m.fichier, "%s  [%s]  %s\n", time.Now().Format("2006-01-02 15:04:05"), typ, texte)
	}
	id := m.scanID
	m.mu.Unlock()
	if id != "" && etape >= 0 {
		var p *int
		if progression >= 0 {
			p = &progression
		}
		if typ == "critique" || typ == "constat" {
			typ = "info" // l'agent ne qualifie jamais de constat : c'est le rôle du serveur
		}
		if err := m.client.EnvoyerEvenements(id, []api.Evenement{{Etape: etape, Type: typ, Texte: texte, Progression: p}}); err != nil {
			m.mu.Lock()
			m.etat.Journal = append(m.etat.Journal, Ligne{Heure: time.Now().Format("15:04:05"), Type: "erreur",
				Texte: "Journal non transmis au serveur : " + err.Error()})
			m.mu.Unlock()
		}
	}
}

// progresser met à jour la barre de progression sans ajouter de ligne au journal.
func (m *Mission) progresser(p int) {
	m.mu.Lock()
	m.etat.Progression = p
	m.mu.Unlock()
}

func (m *Mission) echouer(err error) error {
	m.log(-1, "erreur", err.Error(), -1)
	m.mu.Lock()
	m.etat.Statut, m.etat.Message, m.occupe = StatutErreur, err.Error(), false
	m.scanID = ""
	if m.fichier != nil {
		_ = m.fichier.Close()
		m.fichier = nil
	}
	m.mu.Unlock()
	return err
}

// Lancer exécute la collecte (bloquant). Appeler dans une goroutine depuis l'interface.
func (m *Mission) Lancer(ctx context.Context) error {
	m.mu.Lock()
	if m.occupe {
		m.mu.Unlock()
		return fmt.Errorf("un scan est déjà en cours")
	}
	m.occupe = true
	m.etat = Instantane{Statut: StatutScan, Etape: Etapes[0], Mode: m.etat.Mode}
	m.obs = nil
	nom := filepath.Join(m.dossierJx, "scan-"+time.Now().Format("20060102-150405")+".log")
	m.fichier, _ = os.OpenFile(nom, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	m.mu.Unlock()

	mode := map[bool]string{true: "demo", false: "reel"}[m.demo]
	debut, err := m.client.DemarrerScan(mode)
	if err != nil {
		return m.echouer(fmt.Errorf("scan refusé par le serveur : %w", err))
	}
	if err := debut.Politique.VerifierLectureSeule(); err != nil {
		return m.echouer(err)
	}
	m.mu.Lock()
	m.scanID = debut.ScanID
	m.mu.Unlock()
	m.log(0, "info", fmt.Sprintf("Scan autorisé par le mandat %s. Lecture seule : aucune intrusion, aucune exploitation, aucune modification.", debut.Mandat), 2)
	if m.demo {
		m.log(0, "info", "Mode démonstration : le réseau est simulé, l'appairage et la transmission sont réels.", 3)
	}

	t0 := time.Now()
	var obs *scan.Observations
	if m.demo {
		obs, err = m.collecteDemo(ctx)
	} else {
		obs, err = m.collecteReelle(ctx, debut.Politique)
	}
	if err != nil {
		return m.echouer(err)
	}
	obs.VersionAgent, obs.Debut, obs.Fin = m.version, t0.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)
	for _, n := range obs.Borner() {
		m.log(6, "info", "Limite du schéma appliquée : "+n+".", -1)
	}
	machines, ports := obs.Compter()
	m.mu.Lock()
	m.obs, m.etat.Machines, m.etat.Ports = obs, machines, ports
	m.mu.Unlock()
	m.exporterBloodHound(obs)
	m.log(6, "ok", fmt.Sprintf("Collecte terminée : %d machines, %d ports ouverts. Résultats prêts à être transmis au cabinet.", machines, ports), 90)
	m.mu.Lock()
	m.etat.Statut, m.etat.Etape, m.occupe = StatutCollecte, "Collecte terminée — prête à être transmise.", false
	m.mu.Unlock()
	return nil
}

// Transmettre envoie les observations ; le serveur les analyse et renvoie la note.
func (m *Mission) Transmettre() (*api.Bilan, error) {
	m.mu.Lock()
	if m.etat.Statut != StatutCollecte || m.obs == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("aucune collecte à transmettre")
	}
	m.occupe = true
	obs, id := m.obs, m.scanID
	m.mu.Unlock()
	m.log(7, "info", "Transmission des observations au cabinet (HTTPS, chaque requête signée)…", 95)
	bilan, corps, err := m.client.EnvoyerResultats(id, obs)
	if err != nil {
		return nil, m.echouer(fmt.Errorf("transmission refusée : %w", err))
	}
	// Le serveur a clos le scan à réception : les lignes suivantes ne sont plus que locales
	// (le serveur ajoute lui-même sa ligne de synthèse au journal du scan).
	m.mu.Lock()
	m.scanID = ""
	m.mu.Unlock()
	// Copie locale exacte de ce qui a été transmis : l'entité sait précisément ce qui a quitté son réseau.
	_ = os.WriteFile(filepath.Join(m.dossierJx, "observations-"+time.Now().Format("20060102-150405")+".json"), corps, 0o600)
	m.log(7, "ok", fmt.Sprintf("Analyse du cabinet : %d constats — score %d/100 — note %s. Empreinte %s.",
		bilan.Constats, bilan.Score, bilan.Note, bilan.Empreinte[:16]), 100)
	m.mu.Lock()
	c, s := bilan.Constats, bilan.Score
	m.etat.Statut, m.etat.Constats, m.etat.Score, m.etat.Note = StatutTransmis, &c, &s, bilan.Note
	m.etat.Annuaire = bilan.Annuaire
	m.etat.Etape = fmt.Sprintf("Scan transmis — %d constats, note %s.", c, bilan.Note)
	m.etat.Message = bilan.Message
	m.scanID, m.occupe = "", false
	if m.fichier != nil {
		_ = m.fichier.Close()
		m.fichier = nil
	}
	m.mu.Unlock()
	return bilan, nil
}

// ----------------------------------------------------------------------------- collecte réelle

func (m *Mission) collecteReelle(ctx context.Context, pol scan.Politique) (*scan.Observations, error) {
	cibles, err := scan.CalculerCibles(pol.PlagesAutorisees, scan.InterfacesLocales(), pol.MaxHotes)
	if err != nil {
		return nil, err
	}
	if len(cibles.Hotes) == 0 {
		return nil, fmt.Errorf("aucun réseau privé autorisé à examiner depuis ce poste")
	}
	m.log(1, "info", fmt.Sprintf("Réseau(x) %s : %d adresses à examiner%s.", strings.Join(cibles.Reseaux, ", "),
		len(cibles.Hotes), map[bool]string{true: " (limite atteinte)", false: ""}[cibles.Tronque]), 8)
	obs := &scan.Observations{Mode: "reel", Reseaux: cibles.Reseaux}

	profil, connu := scan.ProfilDepuis(m.profilEffectif(pol.Profil))
	if !connu {
		m.log(2, "erreur", fmt.Sprintf("Profil de scan inconnu (%q) : profil Standard appliqué.", pol.Profil), -1)
	}
	ports := profil.Ports(pol.Ports, pol.InclureFragiles)
	m.log(1, "info", fmt.Sprintf("Profil de scan : %s (%d ports examinés%s).", profil.Libelle, len(ports),
		map[bool]string{true: ", équipements fragiles exclus", false: ""}[profil.ExclureFragiles && !pol.InclureFragiles]), 10)
	if x, err := outils.PreparerNmap(m.nmap); err == nil {
		defer x.Fermer() // verrou d'écriture conservé jusqu'à la fin de la collecte
		scripts, refuses := scan.ScriptsAutorises(pol.ScriptsNSE)
		if len(refuses) > 0 {
			m.log(2, "erreur", "Scripts demandés hors liste blanche, ignorés : "+strings.Join(refuses, ", ")+".", -1)
		}
		if !profil.Scripts {
			scripts = nil
		}
		version := scan.VersionNmap(ctx, x)
		m.log(2, "info", fmt.Sprintf("Nmap %s (signé « %s », empreinte %s…) : connexions TCP sans droits administrateur, détection des versions, scripts « safe » : %s.",
			version, x.Signataire, x.SHA256[:12], valeurOu(strings.Join(scripts, ", "), "aucun")), 15)
		derniereEtape := ""
		hotes, meta, err := scan.ExecuterNmap(ctx, x, profil, cibles.Hotes, pol.Ports, scripts, pol.Timing, pol.InclureFragiles,
			func(a scan.AvancementNmap) {
				// Barre : 15 % -> 60 % pendant Nmap ; une ligne de journal à chaque nouvelle étape seulement.
				if a.Pourcentage >= 0 {
					m.progresser(15 + int(a.Pourcentage*45/100))
				}
				if a.Etape != derniereEtape {
					derniereEtape = a.Etape
					m.log(2, "info", "Nmap : "+a.Etape+dureeRestante(a.RestantSecs)+".", -1)
				}
			})
		if err != nil {
			m.log(2, "erreur", err.Error()+" — repli sur le scanner natif.", -1)
		} else {
			meta["version"] = version
			obs.Hotes, obs.Nmap = hotes, meta
			// Compléments natifs non intrusifs : versions TLS et exigence d'authentification HTTP.
			for i := range obs.Hotes {
				scan.Completer(ctx, &obs.Hotes[i])
			}
		}
	} else {
		m.log(2, "info", "Nmap indisponible ou non vérifié ("+err.Error()+") : scanner natif (connexions TCP, bannières, versions TLS).", 15)
	}
	if obs.Hotes == nil {
		obs.Hotes = scan.ScannerNatifProfil(ctx, cibles.Hotes, ports, profil.ConcurrenceNative(), func(fait, total int) {
			if total > 0 && fait%16 == 0 {
				m.progresser(15 + fait*45/total)
			}
		})
		obs.Nmap = map[string]any{"moteur": "natif", "profil": string(profil.Nom)}
	}
	m.log(1, "info", fmt.Sprintf("%d machines répondent sur le réseau.", len(obs.Hotes)), 60)
	for i := range obs.Hotes {
		scan.DevinerType(&obs.Hotes[i])
		m.log(2, "info", scan.Resume(obs.Hotes[i]), -1)
	}

	// Inventaire du poste local (lecture seule), rattaché à l'hôte qui porte l'adresse du poste.
	m.log(3, "info", "Inventaire du poste qui exécute l'agent…", 65)
	inv, sys := scan.CollecterInventaire(ctx, func(s string) { m.log(3, "info", s, -1) })
	if inv != nil {
		m.rattacherInventaire(obs, inv, sys)
		m.resumerInventaire(inv)
	}
	m.collecteComplementaire(ctx, obs, pol, profil)
	return obs, nil
}

func (m *Mission) rattacherInventaire(obs *scan.Observations, inv *scan.Inventaire, sys *scan.SystemeExploitation) {
	locales := scan.AdressesLocales()
	for i := range obs.Hotes {
		if locales[obs.Hotes[i].IP] {
			obs.Hotes[i].Inventaire = inv
			if sys != nil {
				obs.Hotes[i].OS = sys
			}
			return
		}
	}
	// Le poste lui-même n'est pas dans les plages examinées : il est ajouté pour son inventaire.
	ip := "127.0.0.1"
	var ips []string
	for a := range locales {
		if a != "127.0.0.1" {
			ips = append(ips, a)
		}
	}
	sort.Strings(ips)
	if len(ips) > 0 {
		ip = ips[0]
	}
	nom, _ := os.Hostname()
	obs.Hotes = append(obs.Hotes, scan.Hote{IP: ip, Nom: strings.ToUpper(nom), Type: "poste", OS: sys, Inventaire: inv})
}

func (m *Mission) resumerInventaire(inv *scan.Inventaire) {
	m.log(3, "info", fmt.Sprintf("%d logiciels inventoriés sur le poste.", len(inv.Logiciels)), 72)
	dernier := ""
	for _, c := range inv.Correctifs {
		if c.InstalleLe != nil && *c.InstalleLe > dernier {
			dernier = *c.InstalleLe
		}
	}
	m.log(4, "info", fmt.Sprintf("%d correctifs installés ; dernier installé le %s.", len(inv.Correctifs), valeurOu(dernier, "date inconnue")), 78)
	if inv.Antivirus != nil {
		age := "âge des signatures inconnu"
		if inv.Antivirus.SignaturesAgeJours != nil {
			age = fmt.Sprintf("signatures de %d jour(s)", *inv.Antivirus.SignaturesAgeJours)
		}
		m.log(5, "info", fmt.Sprintf("Antivirus : %s, %s, %s.", valeurOu(inv.Antivirus.Produit, "produit inconnu"),
			map[bool]string{true: "actif", false: "inactif"}[inv.Antivirus.Actif], age), 82)
	}
	m.log(5, "info", fmt.Sprintf("%d partage(s) réseau relevé(s).", len(inv.Partages)), -1)
	m.log(6, "info", fmt.Sprintf("%d compte(s) local(aux) relevé(s).", len(inv.Comptes)), 86)
	if inv.Sauvegardes != nil && inv.Sauvegardes.Derniere != nil {
		m.log(6, "info", "Dernière sauvegarde système : "+*inv.Sauvegardes.Derniere+".", -1)
	} else {
		m.log(6, "info", "Aucun historique de sauvegarde système lisible : point à documenter par le cabinet.", -1)
	}
}

func valeurOu(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ----------------------------------------------------------------------------- collecte de démonstration

func (m *Mission) collecteDemo(ctx context.Context) (*scan.Observations, error) {
	o, err := demo.Observations(time.Now())
	if err != nil {
		return nil, err
	}
	pause := func(d time.Duration) {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}
	m.log(1, "info", fmt.Sprintf("Réseau %s : %d machines trouvées.", strings.Join(o.Reseaux, ", "), len(o.Hotes)), 10)
	pause(400 * time.Millisecond)
	for i, h := range o.Hotes {
		m.mu.Lock()
		m.etat.Machines = i + 1
		m.etat.Ports += len(h.Ports)
		m.mu.Unlock()
		m.log(2, "info", scan.Resume(h), 12+i*5)
		pause(250 * time.Millisecond)
	}
	nl, nc := 0, 0
	for _, h := range o.Hotes {
		if h.Inventaire != nil {
			nl += len(h.Inventaire.Logiciels)
			nc += len(h.Inventaire.Correctifs)
		}
	}
	m.log(3, "info", fmt.Sprintf("%d logiciels relevés sur les postes inventoriés.", nl), 65)
	pause(300 * time.Millisecond)
	m.log(4, "info", fmt.Sprintf("%d correctifs relevés ; dates d'installation transmises pour analyse.", nc), 72)
	pause(300 * time.Millisecond)
	m.log(5, "info", "Versions des protocoles de partage, signature SMB, accès anonymes et chiffrement relevés.", 80)
	pause(300 * time.Millisecond)
	m.log(6, "info", "Comptes locaux, partages, sauvegardes et journalisation relevés.", 86)
	pause(300 * time.Millisecond)
	if o.AD != nil {
		m.log(6, "info", "Annuaire Active Directory : lecture LDAP chiffrée (comptes, groupes, droits, délégations)…", 87)
		pause(300 * time.Millisecond)
		m.log(6, "info", fmt.Sprintf("Annuaire %s : %d objets, %d relations de contrôle relevées (lecture seule).",
			o.AD.Domaine.Nom, len(o.AD.Noeuds), len(o.AD.Aretes)), 88)
		pause(200 * time.Millisecond)
	}
	o.Nmap = map[string]any{"moteur": "demo"}
	return &o, nil
}

// JSON utilitaire (mode console).
func (i Instantane) JSON() string {
	b, _ := json.MarshalIndent(i, "", "  ")
	return string(b)
}

// dureeRestante : « (environ 4 min restantes) » d'après l'estimation de Nmap.
func dureeRestante(secs int) string {
	switch {
	case secs <= 0:
		return ""
	case secs < 90:
		return fmt.Sprintf(" (environ %d s restantes)", secs)
	default:
		return fmt.Sprintf(" (environ %d min restantes)", (secs+30)/60)
	}
}

// exporterBloodHound écrit l'export BloodHound CE de l'annuaire collecté dans le dossier des journaux
// remis au client (l'analyse, elle, reste faite par le serveur). Sans annuaire : rien.
func (m *Mission) exporterBloodHound(obs *scan.Observations) {
	if obs.AD == nil {
		return
	}
	chemin, err := annuaire.ExporterBloodHound(obs.AD, m.dossierJx, time.Now())
	if err != nil {
		m.log(6, "erreur", "Export BloodHound impossible : "+err.Error(), -1)
		return
	}
	m.mu.Lock()
	m.etat.ExportBloodHound = chemin
	m.mu.Unlock()
	m.log(6, "info", "Export BloodHound CE de l'annuaire enregistré : "+filepath.Base(chemin)+
		" (à importer dans BloodHound CE : « Upload Data »).", -1)
}

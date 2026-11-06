package app

import (
	"context"
	"errors"
	"sync"

	"cacyber/agent/internal/etat"
	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
)

// Mise en place de l'outillage open source (brief §12.2) : téléchargement depuis les sources
// officielles, vérification, auto-test, journal remis au client. Partagé par l'interface et la CLI.

// Statuts de l'outillage.
const (
	OutillageInconnu      = "inconnu"
	OutillageInstallation = "installation"
	OutillagePret         = "pret"
	OutillageErreur       = "erreur"
)

// EtatOutillage : état affiché par l'interface.
type EtatOutillage struct {
	Statut      string          `json:"statut"`
	Etape       string          `json:"etape"`
	Progression int             `json:"progression"`
	Rapport     *outils.Rapport `json:"rapport,omitempty"`
	Message     string          `json:"message"`
	Journal     string          `json:"journal,omitempty"`
}

type outillage struct {
	mu   sync.Mutex
	etat EtatOutillage
}

func (a *App) gestionnaire(progres func(outils.Etape)) (*outils.Gestionnaire, error) {
	return outils.Nouveau(outils.DossierParDefaut(), etat.Securiser, progres)
}

// Outillage renvoie l'état courant de la mise en place.
func (a *App) Outillage() EtatOutillage {
	a.outil.mu.Lock()
	defer a.outil.mu.Unlock()
	e := a.outil.etat
	if e.Statut == "" {
		e.Statut = OutillageInconnu
	}
	return e
}

func (a *App) majOutillage(f func(e *EtatOutillage)) {
	a.outil.mu.Lock()
	f(&a.outil.etat)
	a.outil.mu.Unlock()
}

// InstallerOutillage lance la mise en place en arrière-plan (interface).
func (a *App) InstallerOutillage(ctx context.Context) error {
	a.outil.mu.Lock()
	if a.outil.etat.Statut == OutillageInstallation {
		a.outil.mu.Unlock()
		return errors.New("mise en place déjà en cours")
	}
	a.outil.etat = EtatOutillage{Statut: OutillageInstallation, Etape: "Préparation…"}
	a.outil.mu.Unlock()
	go func() { _, _ = a.InstallerOutillageEtAttendre(ctx, nil) }()
	return nil
}

// InstallerOutillageEtAttendre installe (ou contrôle) osquery, exécute
// l'auto-test et consigne le bilan dans le journal local. Bloquant (CLI).
func (a *App) InstallerOutillageEtAttendre(ctx context.Context, progres func(outils.Etape)) (*outils.Rapport, error) {
	a.majOutillage(func(e *EtatOutillage) { *e = EtatOutillage{Statut: OutillageInstallation, Etape: "Préparation…"} })
	g, err := a.gestionnaire(func(et outils.Etape) {
		a.majOutillage(func(e *EtatOutillage) {
			e.Etape = et.Texte
			if et.Progression >= 0 {
				e.Progression = et.Progression
			}
		})
		if progres != nil {
			progres(et)
		}
	})
	if err != nil {
		a.majOutillage(func(e *EtatOutillage) { e.Statut, e.Message = OutillageErreur, err.Error() })
		return nil, err
	}
	_, errInst := g.Installer(ctx)
	if progres != nil {
		progres(outils.Etape{Outil: "auto-test", Texte: "Auto-test sur 127.0.0.1…", Progression: -1})
	}
	a.majOutillage(func(e *EtatOutillage) { e.Etape = "Auto-test sur le poste (127.0.0.1)…" })
	r := g.AutoTest(ctx, a.opt.Nmap)
	if errInst != nil {
		r.Message += " Installation incomplète : " + errInst.Error()
	}
	chemin, errJ := journal.ConsignerOutillage(a.dossier.CheminJournaux(), r)
	a.majOutillage(func(e *EtatOutillage) {
		e.Statut, e.Rapport, e.Message, e.Journal, e.Progression = OutillagePret, &r, r.Message, chemin, 100
		e.Etape = r.Message
		if errInst != nil {
			e.Statut = OutillageErreur
		}
	})
	if errJ != nil {
		return &r, errJ
	}
	return &r, errInst
}

// EtatOutils : contrôle des composants sans téléchargement (CLI --etat-outils).
func (a *App) EtatOutils() ([]outils.EtatOutil, error) {
	g, err := a.gestionnaire(nil)
	if err != nil {
		return nil, err
	}
	res := g.Etat()
	if x, err := outils.PreparerNmap(a.opt.Nmap); err == nil {
		res = append(res, x.Etat("installation du poste, signature vérifiée"))
		x.Fermer()
	} else {
		res = append(res, outils.EtatOutil{Nom: "nmap", Licence: outils.NmapInstallateur.Licence, Detail: err.Error()})
	}
	return res, nil
}

// InstallerNmap : SUR DEMANDE de l'utilisateur, télécharge l'installateur officiel de Nmap, le
// vérifie (empreinte + signature) et l'ouvre en mode interactif (fenêtre UAC de Windows).
func (a *App) InstallerNmap(ctx context.Context) error {
	if x, err := outils.PreparerNmap(a.opt.Nmap); err == nil {
		x.Fermer()
		return errors.New("Nmap est déjà installé et vérifié sur ce poste")
	}
	g, err := a.gestionnaire(nil)
	if err != nil {
		return err
	}
	chemin, err := g.PreparerInstallateurNmap(ctx)
	if err != nil {
		return err
	}
	return outils.LancerInstallateurNmap(chemin)
}

// OuvrirNpcap ouvre la page officielle de Npcap (option des scans avancés), sur demande.
func (a *App) OuvrirNpcap() error { return outils.OuvrirPageNpcap() }

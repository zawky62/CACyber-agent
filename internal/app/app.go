// Package app réunit l'état de l'agent (identité, site relié, mission en cours) et les actions
// offertes à l'utilisateur : relier le poste, lancer le scan, transmettre, changer de code.
// Il est utilisé à l'identique par l'interface locale et par le mode console.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"cacyber/agent/internal/api"
	"cacyber/agent/internal/etat"
	"cacyber/agent/internal/journal"
)

// FormatCode : format des codes d'appairage émis par la console (CACC-XXXX-XXXX-XXXX-XXXX).
var FormatCode = regexp.MustCompile(`^CACC(-[A-Z0-9]{4}){4}$`)

// NormaliserCode retire les espaces et passe en majuscules.
func NormaliserCode(c string) string { return strings.ToUpper(strings.Join(strings.Fields(c), "")) }

// Options : paramètres de lancement (issus de la ligne de commande).
type Options struct {
	Serveur    *url.URL
	Demo       bool
	Dev        bool
	Nmap       string
	CAEpinglee []byte
	Version    string
}

// App : l'agent en cours d'exécution.
type App struct {
	mu      sync.Mutex
	opt     Options
	dossier *etat.Dossier
	etat    *etat.Etat
	client  *api.Client
	mission *journal.Mission
	outil   outillage
}

// Nouvelle ouvre le dossier de l'agent et recharge un éventuel appairage existant.
func Nouvelle(opt Options, d *etat.Dossier) (*App, error) {
	a := &App{opt: opt, dossier: d}
	e, err := d.Charger()
	if err != nil {
		return nil, err
	}
	if e != nil {
		if err := a.activer(e); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *App) activer(e *etat.Etat) error {
	c, err := api.NouveauClient(e, a.dossier)
	if err != nil {
		return err
	}
	a.etat, a.client = e, c
	a.mission = journal.Nouvelle(c, a.opt.Demo, a.opt.Nmap, a.opt.Version, a.dossier.CheminJournaux())
	return nil
}

// Contexte : informations affichées sur la carte « Site relié ».
type Contexte struct {
	Relie   bool                `json:"relie"`
	Site    string              `json:"site,omitempty"`
	SIRET   string              `json:"siret,omitempty"`
	Client  string              `json:"client,omitempty"`
	Cabinet string              `json:"cabinet,omitempty"`
	Expire  string              `json:"expire_le,omitempty"`
	Demo    bool                `json:"demo"`
	Version string              `json:"version"`
	Mission *journal.Instantane `json:"mission,omitempty"`
	// Outillage : mise en place des outils open source (Nmap, osquery, Nuclei) et auto-test.
	Outillage EtatOutillage `json:"outillage"`
}

// Contexte renvoie l'état affichable.
func (a *App) Contexte() Contexte {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := Contexte{Demo: a.opt.Demo, Version: a.opt.Version, Outillage: a.Outillage()}
	if a.etat != nil {
		c.Relie, c.Site, c.SIRET, c.Client, c.Cabinet, c.Expire = true, a.etat.Site, a.etat.SIRET, a.etat.Client, a.etat.Cabinet, a.etat.ExpireLe
		i := a.mission.Etat()
		c.Mission = &i
	}
	return c
}

// Relier présente le code d'appairage au serveur et enregistre l'identité du poste.
func (a *App) Relier(code string) error {
	code = NormaliserCode(code)
	if !FormatCode.MatchString(code) {
		return errors.New("code invalide : format attendu CACC-XXXX-XXXX-XXXX-XXXX")
	}
	e, _, err := api.Enroler(a.opt.Serveur, code, a.opt.Version, a.opt.CAEpinglee, a.opt.Dev, a.dossier)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.activer(e)
}

// Verifier interroge le serveur (mTLS) pour confirmer que le mandat couvre toujours le site.
func (a *App) Verifier() (*api.Moi, error) {
	a.mu.Lock()
	c := a.client
	a.mu.Unlock()
	if c == nil {
		return nil, errors.New("poste non relié")
	}
	return c.Moi()
}

// Lancer démarre la collecte en arrière-plan.
func (a *App) Lancer(ctx context.Context) error {
	a.mu.Lock()
	m := a.mission
	a.mu.Unlock()
	if m == nil {
		return errors.New("poste non relié : saisissez d'abord le code d'appairage")
	}
	go func() { _ = m.Lancer(ctx) }()
	return nil
}

// LancerEtAttendre exécute la collecte de façon bloquante (mode console).
func (a *App) LancerEtAttendre(ctx context.Context) error {
	if a.mission == nil {
		return errors.New("poste non relié")
	}
	return a.mission.Lancer(ctx)
}

// Transmettre envoie les observations collectées.
func (a *App) Transmettre() (*api.Bilan, error) {
	a.mu.Lock()
	m := a.mission
	a.mu.Unlock()
	if m == nil {
		return nil, errors.New("poste non relié")
	}
	return m.Transmettre()
}

// Oublier efface l'appairage local (« Changer de code »). L'agent reste révocable côté serveur.
func (a *App) Oublier() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mission != nil && a.mission.Etat().Statut == journal.StatutScan {
		return errors.New("un scan est en cours")
	}
	if err := a.dossier.Oublier(); err != nil {
		return fmt.Errorf("impossible d'effacer l'appairage : %w", err)
	}
	a.etat, a.client, a.mission = nil, nil, nil
	return nil
}

// Mission courante (mode console).
func (a *App) Mission() *journal.Mission { return a.mission }

// Relie indique si le poste est relié à un site.
func (a *App) Relie() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.etat != nil
}

// NomHote du poste (affichage).
func NomHote() string { h, _ := os.Hostname(); return h }

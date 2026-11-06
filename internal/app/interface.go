package app

// Actions propres à l'interface graphique native : choix du profil de scan, bascule du mode
// démonstration, purge des données locales (désinstallation). Fichier séparé : le cœur de l'agent
// (app.go) reste inchangé et commun au mode console.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
)

// DefinirProfil retient le profil de scan choisi sur le poste ("" = profil proposé par le serveur).
func (a *App) DefinirProfil(nom string) error {
	a.mu.Lock()
	m := a.mission
	a.mu.Unlock()
	if m == nil {
		return errors.New("poste non relié")
	}
	return m.DefinirProfil(nom)
}

// Profil renvoie le profil choisi sur le poste ("" = profil du serveur).
func (a *App) Profil() string {
	a.mu.Lock()
	m := a.mission
	a.mu.Unlock()
	if m == nil {
		return ""
	}
	return m.ProfilLocal()
}

// DefinirDemo bascule entre scan réel et démonstration (réseau simulé). La mission est recréée :
// impossible pendant un scan ou avant transmission d'une collecte.
func (a *App) DefinirDemo(demo bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.opt.Demo == demo {
		return nil
	}
	if a.mission != nil {
		switch a.mission.Etat().Statut {
		case journal.StatutScan:
			return errors.New("un scan est en cours")
		case journal.StatutCollecte:
			return errors.New("une collecte attend d'être transmise")
		}
	}
	profil := ""
	if a.mission != nil {
		profil = a.mission.ProfilLocal()
	}
	a.opt.Demo = demo
	if a.client != nil {
		a.mission = journal.Nouvelle(a.client, demo, a.opt.Nmap, a.opt.Version, a.dossier.CheminJournaux())
		_ = a.mission.DefinirProfil(profil)
	}
	return nil
}

// Demo indique si le mode démonstration est actif.
func (a *App) Demo() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.opt.Demo
}

// Serveur : adresse de la plateforme (affichage).
func (a *App) Serveur() string {
	if a.opt.Serveur == nil {
		return ""
	}
	return a.opt.Serveur.String()
}

// DossierDonnees : dossier de l'agent (identité, journaux).
func (a *App) DossierDonnees() string { return a.dossier.Racine }

// DossierJournaux : journaux remis au client.
func (a *App) DossierJournaux() string { return a.dossier.CheminJournaux() }

// Purger efface les données locales de l'agent (désinstallation propre, brief §12.4) : identité
// (clé, appairage), outillage installé, et, si demandé, les journaux. L'exécutable lui-même n'installe
// rien d'autre : il suffit ensuite de le supprimer. L'agent reste révocable côté serveur.
func (a *App) Purger(avecJournaux bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mission != nil && a.mission.Etat().Statut == journal.StatutScan {
		return errors.New("un scan est en cours : attendez sa fin avant de purger")
	}
	if a.outil.etat.Statut == OutillageInstallation {
		return errors.New("la mise en place de l'outillage est en cours")
	}
	var erreurs []error
	if err := a.dossier.Oublier(); err != nil {
		erreurs = append(erreurs, err)
	}
	a.etat, a.client, a.mission = nil, nil, nil
	if err := os.RemoveAll(outils.DossierParDefaut()); err != nil {
		erreurs = append(erreurs, fmt.Errorf("outillage : %w", err))
	}
	// Ancien profil de la fenêtre WebView2 (versions précédentes de l'agent).
	_ = os.RemoveAll(filepath.Join(a.dossier.Racine, "fenetre"))
	if avecJournaux {
		if err := os.RemoveAll(a.dossier.CheminJournaux()); err != nil {
			erreurs = append(erreurs, fmt.Errorf("journaux : %w", err))
		}
	}
	return errors.Join(erreurs...)
}

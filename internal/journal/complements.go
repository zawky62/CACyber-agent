package journal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cacyber/agent/internal/annuaire"
	"cacyber/agent/internal/authinv"
	"cacyber/agent/internal/identifiants"
	"cacyber/agent/internal/outils"
	"cacyber/agent/internal/scan"
)

// Complements : collectes complémentaires d'une mission réelle (brief §14 et §15.3), toutes en
// lecture seule : contrôles web passifs, osquery (poste local), annuaire AD (LDAP), inventaire
// authentifié (WinRM / SSH). Les identifiants sont fournis localement par l'entité, gardés en mémoire
// et EFFACÉS à la fin de la collecte.
type Complements struct {
	DomaineAD      string
	IdentifiantsAD *identifiants.Identifiants
	Auth           authinv.Options
}

// DefinirComplements fixe les paramètres de la prochaine collecte (identifiants compris).
func (m *Mission) DefinirComplements(c Complements) {
	m.mu.Lock()
	m.complements = c
	m.mu.Unlock()
}

// effacerIdentifiants : aucun identifiant ne survit à la collecte.
func (c *Complements) effacerIdentifiants() {
	c.IdentifiantsAD.Effacer()
	c.Auth.Windows.Effacer()
	c.Auth.Linux.Effacer()
}

// collecteComplementaire enrichit les observations d'une collecte réelle.
func (m *Mission) collecteComplementaire(ctx context.Context, obs *scan.Observations, pol scan.Politique, profil scan.ParametresProfil) {
	m.mu.Lock()
	c := m.complements
	m.mu.Unlock()
	defer c.effacerIdentifiants()

	// 1) Contrôles web passifs (TLS, en-têtes, technologies) — pas en profil industriel, sauf accord.
	if profil.ExclureFragiles && !pol.InclureFragiles {
		m.log(5, "info", "Profil industriel : contrôles web non réalisés (équipements fragiles).", -1)
	} else {
		m.log(5, "info", "Contrôles web passifs : certificats, chiffrements, en-têtes de sécurité (une requête par service).", 70)
		obs.Web = scan.ControlerWeb(ctx, obs.Hotes)
		m.log(5, "info", fmt.Sprintf("%d service(s) web examiné(s).", len(obs.Web)), -1)
	}

	// 2) osquery (poste local), binaire signé par l'éditeur vérifié juste avant l'exécution.
	if g, err := outils.Nouveau(outils.DossierParDefaut(), nil, nil); err == nil {
		if x, err := g.Preparer(outils.Osquery); err == nil {
			if o, err := scan.CollecterOsquery(ctx, x); err == nil {
				obs.Osquery = o
				m.log(3, "info", fmt.Sprintf("osquery %s (signé « %s ») : %d programmes, %d volume(s) BitLocker lus.", o.Version,
					x.Signataire, o.NbProgrammes, len(o.BitLocker)), -1)
			}
			x.Fermer()
		} else {
			m.log(3, "info", "osquery non disponible ("+err.Error()+") : compléments du poste non collectés.", -1)
		}
	}

	// 3) Annuaire Active Directory (LDAP chiffré, lecture seule), si la politique ne l'exclut pas.
	if strings.EqualFold(pol.CollecteAD, "aucune") {
		m.log(6, "info", "Collecte de l'annuaire désactivée par le mandat.", -1)
	} else {
		m.log(6, "info", "Annuaire Active Directory : lecture LDAP chiffrée (comptes, groupes, droits, délégations)…", 78)
		a, err := annuaire.Collecter(ctx, annuaire.Options{Domaine: c.DomaineAD, Identifiants: c.IdentifiantsAD,
			Journal: func(s string) { m.log(6, "info", s, -1) }})
		switch {
		case errors.Is(err, annuaire.ErrHorsDomaine):
			m.log(6, "info", "Poste hors domaine Active Directory : annuaire non collecté.", -1)
		case err != nil:
			m.log(6, "erreur", "Annuaire non collecté : "+err.Error(), -1)
		default:
			obs.AD = a
			m.log(6, "info", fmt.Sprintf("Annuaire %s : %d objets, %d relations de contrôle relevées%s.", a.Domaine.Nom,
				len(a.Noeuds), len(a.Aretes), map[bool]string{true: " (limite atteinte)", false: ""}[a.Tronque]), -1)
		}
	}

	// 4) Inventaire authentifié (identifiants fournis par l'entité).
	if c.Auth.Windows.Present() || c.Auth.Linux.Present() {
		o := c.Auth
		o.Journal = func(s string) { m.log(4, "info", s, -1) }
		obs.InventaireAuth = authinv.Inventorier(ctx, obs, o)
	} else {
		m.log(4, "info", "Inventaire authentifié non demandé (aucun identifiant fourni) : services exposés seulement pour les autres postes.", -1)
	}
}

//go:build !windows

package annuaire

import (
	"errors"

	"cacyber/agent/internal/identifiants"
)

// lier (hors Windows) : liaison simple, UNIQUEMENT sur une session déjà chiffrée par TLS (LDAPS ou
// StartTLS), avec les identifiants fournis par l'entité. Sans identifiants, aucune liaison anonyme.
func lier(s *session, domaine string, id *identifiants.Identifiants) error {
	if !id.Present() {
		return errors.New("identifiants requis hors Windows (aucune liaison anonyme)")
	}
	return id.Avec(func(mdp string) error {
		dom := id.Domaine
		if dom == "" {
			dom = domaine
		}
		return s.c.Bind(id.Utilisateur+"@"+dom, mdp)
	})
}

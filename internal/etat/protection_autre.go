//go:build !windows

package etat

// Hors Windows : permissions POSIX 0700 / 0600 (appliquées à la création), pas de DPAPI.
// La clé est stockée en PEM, lisible du seul propriétaire.

func proteger(clair []byte) ([]byte, error)    { return clair, nil }
func deproteger(donnee []byte) ([]byte, error) { return donnee, nil }

func securiserDossier(_ string, _ bool) error { return nil }

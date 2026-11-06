//go:build !windows

package scan

import (
	"context"
	"strings"
)

// Hors Windows, l'inventaire local n'est pas encore implémenté : l'agent se limite à la
// découverte réseau (le cas d'usage cible est le parc Windows des entités contrôlées).
func CollecterInventaire(_ context.Context, note func(string)) (*Inventaire, *SystemeExploitation) {
	note("Inventaire local non disponible sur ce système : découverte réseau uniquement.")
	return nil, nil
}

// AnalyserNetAccounts : voir la version Windows (utilisée aussi par les tests).
func AnalyserNetAccounts(string) *PolitiqueMdp { return &PolitiqueMdp{} }

// AnalyserAuditpol : voir la version Windows.
func AnalyserAuditpol(s string) (bool, bool) { return strings.Contains(s, "x"), false }

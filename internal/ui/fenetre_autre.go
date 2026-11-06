//go:build !windows

package ui

// Hors Windows : pas de fenêtre native embarquée ; l'appelant se replie sur le navigateur.
func OuvrirFenetre(_, _ string) bool { return false }

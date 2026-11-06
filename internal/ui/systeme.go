package ui

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ouvrirDossier ouvre un dossier local dans l'explorateur de fichiers (action explicite de l'utilisateur).
func ouvrirDossier(chemin string) error {
	st, err := os.Stat(chemin)
	if err != nil || !st.IsDir() {
		return errors.New("le dossier des journaux n'existe pas encore : il est créé au premier scan")
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("explorer.exe", filepath.Clean(chemin)).Start()
	case "darwin":
		return exec.Command("open", chemin).Start()
	default:
		return exec.Command("xdg-open", chemin).Start()
	}
}

// purgerPreferences efface les préférences d'affichage créées par Fyne pour l'agent.
func purgerPreferences() error {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(base, "fyne", IdentifiantApplication))
}

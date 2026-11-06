//go:build !windows

package outils

import (
	"errors"
	"os"
	"os/exec"
)

// Hors Windows : l'outillage géré (binaires Windows du manifeste) n'est pas installé ; Nmap est
// celui du système (paquet de la distribution). Les fonctions restent présentes pour compiler.

func ouvrirVerrouille(chemin string) (*os.File, error) { return os.Open(chemin) }

func verifierAuthenticode(*os.File) error {
	return errors.New("signature Authenticode : contrôle disponible sous Windows uniquement")
}

func ouvrirAdresse(url string) error { return exec.Command("xdg-open", url).Start() }

func lancerInstallateur(string) error {
	return errors.New("installateur Windows : non applicable sur ce système")
}

func sansFenetre(*exec.Cmd) {}

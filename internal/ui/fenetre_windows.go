//go:build windows

package ui

// Fenêtre native de l'agent (Windows) : l'interface est affichée dans une fenêtre appartenant à
// CACCyber-Agent.exe, via le composant WebView2 intégré à Windows 10/11 — pas d'onglet de
// navigateur, pas de barre d'adresse. La page reste servie en local (127.0.0.1, jeton de session).
//
// Si le runtime WebView2 est absent (très ancien poste), repli sur une fenêtre Microsoft Edge en
// mode application (--app), puis, en dernier recours, sur le navigateur par défaut.

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

const (
	largeur = 600
	hauteur = 760
	titre   = "CACyber — Agent de scan"
)

var (
	user32        = syscall.NewLazyDLL("user32.dll")
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLoadImage = user32.NewProc("LoadImageW")
	procSendMsg   = user32.NewProc("SendMessageW")
	procModule    = kernel32.NewProc("GetModuleHandleW")
)

// OuvrirFenetre affiche l'interface dans une fenêtre native et BLOQUE jusqu'à sa fermeture.
// Retourne false si aucune fenêtre native n'a pu être créée (l'appelant se replie alors).
func OuvrirFenetre(url, dossierDonnees string) bool {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		// Profil WebView2 isolé dans le dossier protégé de l'agent (aucun cookie partagé).
		DataPath: filepath.Join(dossierDonnees, "fenetre"),
		WindowOptions: webview2.WindowOptions{
			Title: titre, Width: largeur, Height: hauteur, Center: true,
		},
	})
	if w == nil {
		return ouvrirEdgeApplication(url)
	}
	defer w.Destroy()
	appliquerIcone(uintptr(w.Window()))
	w.SetSize(520, 640, webview2.HintMin)
	w.Navigate(url)
	w.Run() // boucle de messages Windows : rend la main à la fermeture de la fenêtre
	return true
}

// appliquerIcone pose l'icône CACyber (ressource « APP » embarquée dans l'exécutable par
// go-winres) sur la fenêtre et dans la barre des tâches.
func appliquerIcone(hwnd uintptr) {
	module, _, _ := procModule.Call(0)
	nom, _ := syscall.UTF16PtrFromString("APP")
	// Ressource nommée « APP », sinon identifiant numérique 1 (selon l'outil qui a généré le .syso).
	for _, ref := range []uintptr{uintptr(unsafe.Pointer(nom)), 1} {
		trouve := false
		for _, taille := range []struct {
			type_, cx uintptr
		}{{0, 16}, {1, 32}} { // ICON_SMALL, ICON_BIG
			icone, _, _ := procLoadImage.Call(module, ref, 1 /* IMAGE_ICON */, taille.cx, taille.cx, 0)
			if icone != 0 {
				procSendMsg.Call(hwnd, 0x0080 /* WM_SETICON */, taille.type_, icone)
				trouve = true
			}
		}
		if trouve {
			return
		}
	}
}

// ouvrirEdgeApplication : repli sur Edge en mode application (fenêtre sans barre d'adresse).
// Bloque tant que la fenêtre Edge est ouverte.
func ouvrirEdgeApplication(url string) bool {
	for _, base := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		edge := filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(edge); err == nil {
			profil := filepath.Join(os.TempDir(), "cacyber-agent-fenetre")
			cmd := exec.Command(edge, "--app="+url, "--user-data-dir="+profil, "--no-first-run",
				"--window-size=600,760")
			if cmd.Run() == nil {
				return true
			}
		}
	}
	return false
}

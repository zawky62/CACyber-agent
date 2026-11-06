//go:build windows

package main

// L'exécutable est compilé en sous-système « fenêtre » (-H windowsgui) : un double-clic n'ouvre
// aucune console noire. En mode --cli (ou --version), on se rattache à la console du terminal
// parent pour que les messages s'affichent normalement.

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	procAttachConsole = syscall.NewLazyDLL("kernel32.dll").NewProc("AttachConsole")
	procMessageBox    = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
)

// alerte affiche une boîte de dialogue d'erreur (utile quand l'agent est lancé par double-clic).
func alerte(titre, message string) {
	t, _ := syscall.UTF16PtrFromString(titre)
	m, _ := syscall.UTF16PtrFromString(message)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10 /* MB_ICONERROR */)
}

const attacherParent = ^uintptr(0) // ATTACH_PARENT_PROCESS (-1)

func rattacherConsole() {
	// Sortie déjà redirigée (fichier, tube) : on la conserve telle quelle.
	if t, err := syscall.GetFileType(syscall.Handle(os.Stdout.Fd())); err == nil && t != 0 /* FILE_TYPE_UNKNOWN */ {
		return
	}
	if r, _, _ := procAttachConsole.Call(attacherParent); r == 0 {
		return // lancé hors terminal : rien à faire
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}

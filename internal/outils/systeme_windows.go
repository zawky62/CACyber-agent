//go:build windows

package outils

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ouvrirVerrouille ouvre un binaire en lecture en INTERDISANT écriture, renommage et suppression
// tant que le descripteur reste ouvert (partage FILE_SHARE_READ seul). L'empreinte est calculée
// au travers de ce descripteur et il est conservé jusqu'à la fin de l'exécution : le fichier
// vérifié est exactement celui que Windows charge (pas de substitution entre contrôle et lancement).
func ouvrirVerrouille(chemin string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(chemin)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("ouverture de %s : %w", chemin, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, fmt.Errorf("%s est un lien ou un point d'analyse : refusé", chemin)
	}
	return os.NewFile(uintptr(h), chemin), nil
}

// verifierAuthenticode : signature valide selon Windows (empreinte + chaîne de confiance), contrôlée
// sur le descripteur déjà ouvert. Révocation non interrogée en ligne (postes sans Internet), mais
// le cache local de Windows est consulté.
func verifierAuthenticode(f *os.File) error {
	chemin, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	info := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: chemin,
		File:     windows.Handle(f.Fd()),
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(info),
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	errVerif := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if errVerif != nil {
		return fmt.Errorf("signature Authenticode invalide (%s) : %w", f.Name(), errVerif)
	}
	return nil
}

// ouvrirAdresse ouvre une page HTTPS dans le navigateur par défaut (ShellExecute « open »).
func ouvrirAdresse(url string) error {
	verbe, _ := windows.UTF16PtrFromString("open")
	u, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verbe, u, nil, nil, windows.SW_SHOWNORMAL)
}

// lancerInstallateur exécute un installateur en mode INTERACTIF (ShellExecute « open ») : c'est son
// propre manifeste qui demande l'élévation (fenêtre UAC) ; l'utilisateur peut refuser à tout moment.
func lancerInstallateur(chemin string) error {
	return ouvrirAdresse(chemin)
}

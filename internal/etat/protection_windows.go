//go:build windows

package etat

// Durcissement Windows du dossier de l'agent :
//   - ACL protégée (héritage coupé) : SYSTEM, Administrateurs et le compte qui exécute l'agent ;
//   - refus d'un dossier préexistant dont le propriétaire n'est pas de confiance (anti « planting ») ;
//   - clé privée chiffrée par DPAPI (CryptProtectData, portée machine) : copiée sur un autre poste,
//     elle est inutilisable. Bibliothèque standard uniquement (appels directs à crypt32.dll).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	crypt32           = syscall.NewLazyDLL("crypt32.dll")
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procProtectData   = crypt32.NewProc("CryptProtectData")
	procUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree     = kernel32.NewProc("LocalFree")
	entropieDPAPI     = []byte("CACyber-Agent/cle-v1")
	errDPAPI          = errors.New("DPAPI indisponible")
)

const cryptprotectLocalMachine = 0x4 // CRYPTPROTECT_LOCAL_MACHINE : déchiffrable sur ce poste uniquement
const cryptprotectUIForbidden = 0x1

type blob struct {
	taille uint32
	donnee *byte
}

func nouveauBlob(b []byte) *blob {
	if len(b) == 0 {
		return &blob{}
	}
	return &blob{taille: uint32(len(b)), donnee: &b[0]}
}

func (b *blob) octets() []byte {
	out := make([]byte, b.taille)
	copy(out, unsafe.Slice(b.donnee, b.taille))
	return out
}

// proteger chiffre par DPAPI (portée machine).
func proteger(clair []byte) ([]byte, error) {
	var sortie blob
	r, _, err := procProtectData.Call(uintptr(unsafe.Pointer(nouveauBlob(clair))), 0,
		uintptr(unsafe.Pointer(nouveauBlob(entropieDPAPI))), 0, 0,
		cryptprotectLocalMachine|cryptprotectUIForbidden, uintptr(unsafe.Pointer(&sortie)))
	if r == 0 {
		return nil, fmt.Errorf("%w : %v", errDPAPI, err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(sortie.donnee)))
	return sortie.octets(), nil
}

// deproteger déchiffre un blob DPAPI.
func deproteger(chiffre []byte) ([]byte, error) {
	var sortie blob
	r, _, err := procUnprotectData.Call(uintptr(unsafe.Pointer(nouveauBlob(chiffre))), 0,
		uintptr(unsafe.Pointer(nouveauBlob(entropieDPAPI))), 0, 0, cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&sortie)))
	if r == 0 {
		return nil, fmt.Errorf("%w : %v", errDPAPI, err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(sortie.donnee)))
	return sortie.octets(), nil
}

func outilSysteme(nom string) string {
	racine := os.Getenv("SystemRoot")
	if racine == "" {
		racine = `C:\Windows`
	}
	return filepath.Join(racine, "System32", nom)
}

// sidCourant lit le SID du jeton du processus (whoami), pas une variable d'environnement.
func sidCourant() (string, error) {
	out, err := exec.Command(outilSysteme("whoami.exe"), "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		return "", err
	}
	champs := strings.Split(strings.TrimSpace(string(out)), ",")
	sid := strings.Trim(champs[len(champs)-1], `"`)
	if !strings.HasPrefix(sid, "S-1-") {
		return "", errors.New("SID introuvable")
	}
	return sid, nil
}

// securiserDossier applique l'ACL protégée. Un dossier existant dont le propriétaire n'est ni
// SYSTEM, ni les Administrateurs, ni le compte courant est refusé (il a pu être pré-créé par un tiers).
func securiserDossier(d string, existait bool) error {
	sid, err := sidCourant()
	if err != nil {
		return fmt.Errorf("identification du compte : %w", err)
	}
	if existait {
		// Chemin passé entre apostrophes PowerShell (apostrophes internes doublées) : pas d'interprétation.
		chemin := "'" + strings.ReplaceAll(d, "'", "''") + "'"
		out, err := exec.Command(outilSysteme(filepath.Join("WindowsPowerShell", "v1.0", "powershell.exe")), "-NoProfile", "-NonInteractive",
			"-Command", "(Get-Acl -LiteralPath "+chemin+").GetOwner([System.Security.Principal.SecurityIdentifier]).Value").Output()
		if err != nil {
			return fmt.Errorf("lecture du propriétaire de %s : %w", d, err)
		}
		proprio := strings.TrimSpace(string(out))
		if proprio != "S-1-5-18" && proprio != "S-1-5-32-544" && proprio != sid {
			return fmt.Errorf("dossier %s pré-existant avec un propriétaire non fiable (%s) : refusé", d, proprio)
		}
	}
	// Refus des points d'analyse (jonctions, liens symboliques) : le dossier doit être un vrai dossier.
	if fi, err := os.Lstat(d); err != nil || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !fi.IsDir() {
		return fmt.Errorf("dossier %s refusé : lien ou point d'analyse", d)
	}
	res := exec.Command(outilSysteme("icacls.exe"), d, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*"+sid+":(OI)(CI)F")
	if out, err := res.CombinedOutput(); err != nil {
		return fmt.Errorf("ACL de %s non appliquée : %v (%s)", d, err, strings.TrimSpace(string(out)))
	}
	return nil
}

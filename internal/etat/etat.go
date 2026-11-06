// Package etat gère le dossier de l'agent : identité (clé privée, certificat, CA), contexte du
// site relié et journaux de scan.
//
// La clé privée est générée sur le poste et n'en sort jamais ; c'est le SEUL secret détenu par
// l'agent, propre à ce poste et révocable côté serveur. Aucune clé d'API, aucun mot de passe,
// aucune règle d'analyse n'est stockée.
//
// Durcissement (voir protection_windows.go) : sous Windows, dossier à ACL protégée (SYSTEM,
// Administrateurs, compte de l'agent ; héritage coupé ; dossier pré-créé par un tiers refusé) et clé
// chiffrée par DPAPI portée machine. Ailleurs : permissions POSIX 0700 / 0600.
package etat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Etat : contexte persistant d'un agent relié.
type Etat struct {
	AgentID  string `json:"agent_id"`
	Serveur  string `json:"serveur"`  // application principale (appairage)
	URLMTLS  string `json:"url_mtls"` // écoute mTLS des agents
	Site     string `json:"site"`
	SIRET    string `json:"siret"`
	Client   string `json:"client"`
	Cabinet  string `json:"cabinet"`
	ExpireLe string `json:"expire_le"` // fin de validité du certificat (= fin du mandat)
}

// Dossier : emplacement des fichiers de l'agent.
type Dossier struct{ Racine string }

// DossierParDefaut : %ProgramData%\CACyber\Agent sous Windows, sinon le dossier de configuration
// de l'utilisateur. Si l'emplacement n'est pas inscriptible, repli sur le dossier utilisateur.
func DossierParDefaut() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			d := filepath.Join(pd, "CACyber", "Agent")
			if os.MkdirAll(d, 0o700) == nil && inscriptible(d) {
				return d // l'ACL est appliquée et vérifiée par Ouvrir
			}
		}
	}
	if cfg, err := os.UserConfigDir(); err == nil {
		return filepath.Join(cfg, "CACyber", "Agent")
	}
	return "CACyber-Agent"
}

func inscriptible(d string) bool {
	f, err := os.CreateTemp(d, ".test-*")
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	return true
}

// Ouvrir crée le dossier (et son sous-dossier de journaux) si nécessaire.
// Le dossier racine reçoit une ACL protégée ; un dossier pré-existant au propriétaire non fiable est refusé.
func Ouvrir(racine string) (*Dossier, error) {
	_, errStat := os.Stat(racine)
	existait := errStat == nil
	if err := os.MkdirAll(filepath.Join(racine, "journaux"), 0o700); err != nil {
		return nil, fmt.Errorf("dossier de l'agent %s : %w", racine, err)
	}
	if err := securiserDossier(racine, existait); err != nil {
		return nil, err
	}
	return &Dossier{Racine: racine}, nil
}

// LireCle renvoie la clé privée PEM, déchiffrée en mémoire (DPAPI sous Windows).
func (d *Dossier) LireCle() ([]byte, error) {
	brut, err := os.ReadFile(d.CheminCle())
	if err != nil {
		return nil, err
	}
	// Migration : clé écrite en clair par une version antérieure (avant DPAPI) → chiffrée sur place.
	if bytes.HasPrefix(bytes.TrimSpace(brut), []byte("-----BEGIN")) {
		if protegee, err := proteger(brut); err == nil {
			if err := ecrireAtomique(d.CheminCle(), protegee, 0o600); err != nil {
				return nil, fmt.Errorf("migration de la clé : %w", err)
			}
		}
		return brut, nil
	}
	return deproteger(brut)
}

func (d *Dossier) chemin(nom string) string { return filepath.Join(d.Racine, nom) }

// Fichiers de l'identité de l'agent.
func (d *Dossier) CheminCle() string        { return d.chemin("cle.pem") }
func (d *Dossier) CheminCertificat() string { return d.chemin("certificat.pem") }
func (d *Dossier) CheminCA() string         { return d.chemin("ca.pem") }
func (d *Dossier) CheminJournaux() string   { return d.chemin("journaux") }
func (d *Dossier) cheminEtat() string       { return d.chemin("etat.json") }

// Charger lit l'état ; renvoie (nil, nil) si l'agent n'est pas encore relié.
func (d *Dossier) Charger() (*Etat, error) {
	data, err := os.ReadFile(d.cheminEtat())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e Etat
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("etat.json illisible : %w", err)
	}
	for _, f := range []string{d.CheminCle(), d.CheminCertificat(), d.CheminCA()} {
		if _, err := os.Stat(f); err != nil {
			return nil, nil // identité incomplète : appairage à refaire
		}
	}
	return &e, nil
}

// Enregistrer écrit l'identité et l'état de manière atomique (fichier temporaire + renommage).
func (d *Dossier) Enregistrer(e *Etat, clePEM, certPEM, caPEM []byte) error {
	cleProtegee, err := proteger(clePEM) // DPAPI portée machine sous Windows
	if err != nil {
		return err
	}
	for _, f := range []struct {
		chemin string
		data   []byte
		mode   os.FileMode
	}{{d.CheminCle(), cleProtegee, 0o600}, {d.CheminCertificat(), certPEM, 0o644}, {d.CheminCA(), caPEM, 0o644}} {
		if err := ecrireAtomique(f.chemin, f.data, f.mode); err != nil {
			return err
		}
	}
	data, _ := json.MarshalIndent(e, "", "  ")
	return ecrireAtomique(d.cheminEtat(), data, 0o600)
}

// Oublier supprime l'appairage (identité et état) ; les journaux sont conservés.
func (d *Dossier) Oublier() error {
	for _, f := range []string{d.cheminEtat(), d.CheminCle(), d.CheminCertificat(), d.CheminCA()} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ecrireAtomique : fichier temporaire au nom aléatoire créé exclusivement (os.CreateTemp, O_EXCL)
// dans le même dossier protégé, puis renommage atomique.
func ecrireAtomique(chemin string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(chemin), "."+filepath.Base(chemin)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, errW := f.Write(data)
	errC := f.Close()
	if errW == nil {
		errW = errC
	}
	if errW == nil {
		errW = os.Chmod(tmp, mode)
	}
	if errW != nil {
		_ = os.Remove(tmp)
		return errW
	}
	return os.Rename(tmp, chemin)
}

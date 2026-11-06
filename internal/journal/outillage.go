package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cacyber/agent/internal/outils"
)

// ConsignerOutillage écrit, dans le dossier des journaux remis au client, le bilan de la mise en
// place de l'outillage : composants (version, licence, source, empreinte SHA-256, signataire),
// résultats de l'auto-test et décisions prises (refus, repli). Deux fichiers : lisible (.log) et
// structuré (.json). Renvoie le chemin du fichier lisible.
func ConsignerOutillage(dossier string, r outils.Rapport) (string, error) {
	horo := time.Now().Format("20060102-150405")
	var b strings.Builder
	fmt.Fprintf(&b, "CACyber-Agent — outillage open source — %s\n", r.Date)
	fmt.Fprintf(&b, "Usage : audit en LECTURE SEULE, sous mandat signé. Aucune exploitation, intrusion, force brute ni modification.\n\n")
	fmt.Fprintln(&b, "COMPOSANTS")
	for _, c := range r.Composants {
		etat := "INDISPONIBLE"
		if c.Pret {
			etat = "prêt"
		}
		fmt.Fprintf(&b, "- %s %s [%s] — licence %s\n", c.Nom, c.Version, etat, c.Licence)
		if c.Chemin != "" {
			fmt.Fprintf(&b, "    emplacement : %s\n", c.Chemin)
		}
		if c.SHA256 != "" {
			fmt.Fprintf(&b, "    SHA-256     : %s\n", c.SHA256)
		}
		if c.Signataire != "" {
			fmt.Fprintf(&b, "    signé par   : %s (Authenticode vérifié)\n", c.Signataire)
		}
		if c.Source != "" {
			fmt.Fprintf(&b, "    source      : %s\n", c.Source)
		}
		fmt.Fprintf(&b, "    détail      : %s\n", c.Detail)
	}
	fmt.Fprintln(&b, "\nAUTO-TEST (poste local uniquement, 127.0.0.1)")
	for _, t := range r.Tests {
		etat := "ÉCHEC"
		if t.OK {
			etat = "OK"
		}
		fmt.Fprintf(&b, "- %-8s %s — %s\n", t.Outil, etat, t.Detail)
	}
	fmt.Fprintf(&b, "\n%s\n", r.Message)

	if err := os.MkdirAll(dossier, 0o700); err != nil {
		return "", err
	}
	lisible := filepath.Join(dossier, "outillage-"+horo+".log")
	if err := os.WriteFile(lisible, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	js, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(dossier, "outillage-"+horo+".json"), js, 0o600); err != nil {
		return "", err
	}
	return lisible, nil
}

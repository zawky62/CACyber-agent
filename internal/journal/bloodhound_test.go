package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cacyber/agent/internal/demo"
)

// En mode démonstration, l'export BloodHound CE du domaine fictif est écrit dans le dossier des journaux.
func TestExportBloodHoundDemo(t *testing.T) {
	dossier := t.TempDir()
	m := Nouvelle(nil, true, "", "test", dossier)
	o, err := demo.Observations(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m.exporterBloodHound(&o)
	chemin := m.Etat().ExportBloodHound
	if chemin == "" || filepath.Dir(chemin) != dossier || !strings.HasPrefix(filepath.Base(chemin), "bloodhound-brest.local-") {
		t.Fatalf("export attendu dans %s : %q", dossier, chemin)
	}
	if fi, err := os.Stat(chemin); err != nil || fi.Size() == 0 {
		t.Fatalf("archive absente ou vide : %v", err)
	}
}

package etat

import (
	"os"
	"path/filepath"
	"testing"
)

// Un appairage de l'ancienne génération (TLS mutuel) est ignoré : l'agent redemande un code.
func TestAncienAppairageMTLSIgnore(t *testing.T) {
	d, err := Ouvrir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.Racine, "etat.json"), []byte(`{"agent_id":"x","serveur":"http://localhost:8000","url_mtls":"https://localhost:8443"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d.CheminCle(), []byte("cle"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := d.Charger()
	if err != nil || e != nil {
		t.Fatalf("ancien appairage attendu ignoré, obtenu %+v, %v", e, err)
	}
}

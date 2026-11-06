package identifiants

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Le mot de passe n'apparaît jamais à l'affichage ni dans une sérialisation, et il est effaçable.
func TestJamaisDivulgue(t *testing.T) {
	brut := []byte("S3cret-Tres-Long!")
	i := Nouveaux("", `CORP\audit`, brut)
	for _, b := range brut {
		if b != 0 {
			t.Fatal("le tampon d'origine n'a pas été effacé")
		}
	}
	if i.Domaine != "CORP" || i.Utilisateur != "audit" {
		t.Fatalf("domaine / utilisateur mal déduits : %q %q", i.Domaine, i.Utilisateur)
	}
	for _, s := range []string{i.String(), fmt.Sprintf("%v", i), fmt.Sprintf("%+v", i), fmt.Sprintf("%#v", i)} {
		if strings.Contains(s, "S3cret") {
			t.Fatalf("mot de passe divulgué : %s", s)
		}
	}
	if _, err := json.Marshal(i); err == nil {
		t.Fatal("sérialisation JSON acceptée")
	}
	if _, err := json.Marshal(struct{ I *Identifiants }{i}); err == nil {
		t.Fatal("sérialisation JSON imbriquée acceptée")
	}
	var lu string
	_ = i.Avec(func(m string) error { lu = m; return nil })
	if lu != "S3cret-Tres-Long!" {
		t.Fatal("mot de passe inaccessible pendant l'usage")
	}
	i.Effacer()
	if i.Present() || i.Avec(func(string) error { return nil }) == nil {
		t.Fatal("identifiants encore utilisables après effacement")
	}
}

func TestFormatUPN(t *testing.T) {
	i := Nouveaux("", "audit@corp.local", []byte("x"))
	if i.Domaine != "corp.local" || i.Utilisateur != "audit" {
		t.Fatalf("UPN mal analysé : %q %q", i.Domaine, i.Utilisateur)
	}
}

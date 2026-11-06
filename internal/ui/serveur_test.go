package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"cacyber/agent/internal/app"
	"cacyber/agent/internal/etat"
)

// L'interface locale refuse toute requête sans jeton de session, avec un Host étranger
// (protection contre le « DNS rebinding ») ou une action qui ne serait pas un POST JSON.
func TestProtectionsInterfaceLocale(t *testing.T) {
	d, err := etat.Ouvrir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://localhost:8000")
	a, err := app.Nouvelle(app.Options{Serveur: u, Version: "test"}, d)
	if err != nil {
		t.Fatal(err)
	}
	lien, srv, err := Demarrer(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	pu, _ := url.Parse(lien)
	base := "http://" + pu.Host
	jeton := pu.Query().Get("jeton")

	statut := func(req *http.Request) int {
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	get := func(chemin string, entetes map[string]string) int {
		req, _ := http.NewRequest(http.MethodGet, base+chemin, nil)
		for k, v := range entetes {
			if k == "Host" {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
		}
		return statut(req)
	}
	if c := get("/", nil); c != http.StatusForbidden {
		t.Errorf("page sans jeton : %d", c)
	}
	if c := get("/?jeton="+jeton, nil); c != http.StatusOK {
		t.Errorf("page avec jeton : %d", c)
	}
	if c := get("/?jeton="+jeton, map[string]string{"Host": "attaquant.exemple:80"}); c != http.StatusForbidden {
		t.Errorf("Host étranger accepté : %d", c)
	}
	if c := get("/api/etat", nil); c != http.StatusForbidden {
		t.Errorf("API sans jeton : %d", c)
	}
	if c := get("/api/etat", map[string]string{"X-Jeton": jeton}); c != http.StatusOK {
		t.Errorf("API avec jeton : %d", c)
	}
	// Action déclenchée par un formulaire (pas de JSON) : refusée.
	req, _ := http.NewRequest(http.MethodPost, base+"/api/relier", strings.NewReader("code=CACC"))
	req.Header.Set("X-Jeton", jeton)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := statut(req); c != http.StatusUnsupportedMediaType {
		t.Errorf("POST non JSON : %d", c)
	}
	// Code mal formé : refusé localement, avant tout appel au serveur.
	req, _ = http.NewRequest(http.MethodPost, base+"/api/relier", strings.NewReader(`{"code":"ABC"}`))
	req.Header.Set("X-Jeton", jeton)
	req.Header.Set("Content-Type", "application/json")
	if c := statut(req); c != http.StatusBadRequest {
		t.Errorf("code invalide : %d", c)
	}
}

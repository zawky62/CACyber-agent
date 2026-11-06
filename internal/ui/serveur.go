// Package ui sert l'interface locale de l'agent : une page unique embarquée, sur 127.0.0.1
// uniquement, port aléatoire, protégée par un jeton de session aléatoire.
//
// Protections : écoute en boucle locale seulement ; en-tête Host contrôlé (anti « DNS rebinding ») ;
// chaque appel d'API exige le jeton de session (en-tête X-Jeton) ; les actions exigent POST + JSON
// (une page tierce ne peut pas les déclencher par un simple formulaire) ; CSP stricte.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"cacyber/agent/internal/app"
)

//go:embed index.html logo.svg favicon.svg
var fichiers embed.FS

// Serveur de l'interface locale.
type Serveur struct {
	app   *app.App
	jeton string
	hote  string
	ctx   context.Context
}

// Demarrer ouvre l'écoute locale et renvoie l'URL à ouvrir dans le navigateur.
func Demarrer(ctx context.Context, a *app.App) (string, *http.Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	s := &Serveur{app: a, jeton: hex.EncodeToString(b), hote: ln.Addr().String(), ctx: ctx}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /logo.svg", s.statique("logo.svg", "image/svg+xml"))
	mux.HandleFunc("GET /favicon.svg", s.statique("favicon.svg", "image/svg+xml"))
	mux.HandleFunc("GET /api/etat", s.api(s.etat))
	mux.HandleFunc("POST /api/relier", s.api(s.relier))
	mux.HandleFunc("POST /api/lancer", s.api(s.lancer))
	mux.HandleFunc("POST /api/transmettre", s.api(s.transmettre))
	mux.HandleFunc("POST /api/oublier", s.api(s.oublier))
	mux.HandleFunc("POST /api/outillage/installer", s.api(s.installerOutillage))
	mux.HandleFunc("POST /api/outillage/nmap", s.api(s.installerNmap))
	mux.HandleFunc("POST /api/outillage/npcap", s.api(s.npcap))
	srv := &http.Server{Handler: s.garde(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return fmt.Sprintf("http://%s/?jeton=%s", s.hote, s.jeton), srv, nil
}

// garde : contrôle de l'en-tête Host et en-têtes de sécurité sur toutes les réponses.
func (s *Serveur) garde(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.hote {
			http.Error(w, "hôte refusé", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func (s *Serveur) page(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("jeton")), []byte(s.jeton)) != 1 {
		http.Error(w, "Lien de session invalide : relancez CACyber-Agent.", http.StatusForbidden)
		return
	}
	data, _ := fichiers.ReadFile("index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Serveur) statique(nom, mime string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		data, _ := fichiers.ReadFile(nom)
		w.Header().Set("Content-Type", mime)
		_, _ = w.Write(data)
	}
}

// api : jeton de session obligatoire, JSON en entrée (POST) et en sortie.
func (s *Serveur) api(f func(r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Jeton")), []byte(s.jeton)) != 1 {
			http.Error(w, "jeton de session manquant", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON attendu", http.StatusUnsupportedMediaType)
			return
		}
		res, err := f(r)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"erreur": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(res)
	}
}

func (s *Serveur) etat(*http.Request) (any, error) { return s.app.Contexte(), nil }

func (s *Serveur) relier(r *http.Request) (any, error) {
	var corps struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&corps); err != nil {
		return nil, errors.New("requête invalide")
	}
	if err := s.app.Relier(corps.Code); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

func (s *Serveur) lancer(*http.Request) (any, error) {
	if err := s.app.Lancer(s.ctx); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

func (s *Serveur) transmettre(*http.Request) (any, error) {
	if _, err := s.app.Transmettre(); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

func (s *Serveur) oublier(*http.Request) (any, error) {
	if err := s.app.Oublier(); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

// installerOutillage : mise en place (ou contrôle) de l'outillage open source, en arrière-plan.
func (s *Serveur) installerOutillage(*http.Request) (any, error) {
	if err := s.app.InstallerOutillage(s.ctx); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

// installerNmap : téléchargement et vérification de l'installateur officiel, puis ouverture
// interactive (fenêtre UAC) — uniquement sur clic explicite de l'utilisateur.
func (s *Serveur) installerNmap(*http.Request) (any, error) {
	if err := s.app.InstallerNmap(s.ctx); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

// npcap : ouvre la page officielle de Npcap (option des scans avancés).
func (s *Serveur) npcap(*http.Request) (any, error) {
	if err := s.app.OuvrirNpcap(); err != nil {
		return nil, err
	}
	return s.app.Contexte(), nil
}

// OuvrirNavigateur ouvre l'URL dans le navigateur par défaut du poste.
func OuvrirNavigateur(u string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	case "darwin":
		return exec.Command("open", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}

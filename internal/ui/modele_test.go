package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"cacyber/agent/internal/api"
	"cacyber/agent/internal/app"
	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
	"cacyber/agent/internal/scan"
)

func entier(n int) *int { return &n }

// Enchaînement des écrans : on reprend toujours à l'étape utile, sans pouvoir sauter une condition.
func TestEcranConseille(t *testing.T) {
	nonRelie := app.Contexte{}
	relieSansOutils := app.Contexte{Relie: true, Outillage: app.EtatOutillage{Statut: app.OutillageInconnu}}
	relieDemo := app.Contexte{Relie: true, Demo: true}
	pret := app.Contexte{Relie: true, Outillage: app.EtatOutillage{Statut: app.OutillagePret}}
	enScan := app.Contexte{Relie: true, Mission: &journal.Instantane{Statut: journal.StatutScan}}
	transmis := app.Contexte{Relie: true, Mission: &journal.Instantane{Statut: journal.StatutTransmis}}
	cas := []struct {
		nom     string
		c       app.Contexte
		vu      bool
		attendu Ecran
	}{
		{"premier lancement", nonRelie, false, EcranAccueil},
		{"non relié", nonRelie, true, EcranAppairage},
		{"relié, outils absents", relieSansOutils, true, EcranOutillage},
		{"démonstration : outils facultatifs", relieDemo, true, EcranScan},
		{"outils prêts", pret, true, EcranScan},
		{"scan en cours (reprise)", enScan, true, EcranScan},
		{"résultats transmis", transmis, true, EcranResultat},
	}
	for _, c := range cas {
		if got := EcranConseille(c.c, c.vu); got != c.attendu {
			t.Errorf("%s : écran %v, attendu %v", c.nom, got, c.attendu)
		}
	}
}

func TestAccessible(t *testing.T) {
	if Accessible(EcranScan, app.Contexte{}) {
		t.Error("le scan ne doit pas être accessible sans appairage")
	}
	if Accessible(EcranResultat, app.Contexte{Relie: true, Mission: &journal.Instantane{Statut: journal.StatutCollecte}}) {
		t.Error("le résultat n'est accessible qu'après transmission")
	}
	for _, e := range []Ecran{EcranAccueil, EcranAppairage, EcranOutillage, EcranParametres} {
		if !Accessible(e, app.Contexte{}) {
			t.Errorf("%v doit rester accessible (étapes reprenables)", e)
		}
	}
}

func TestConnexion(t *testing.T) {
	horsLigne := &url.Error{Op: "Get", URL: "https://x", Err: &net.OpError{Op: "dial", Err: errors.New("refused")}}
	cas := []struct {
		moi     *api.Moi
		err     error
		attendu Connexion
	}{
		{&api.Moi{MandatValide: true}, nil, ConnexionEnLigne},
		{&api.Moi{MandatValide: false}, nil, ConnexionMandatInvalide},
		{nil, horsLigne, ConnexionHorsLigne},
		{nil, &api.ErreurServeur{Statut: 401, Message: "Signature invalide."}, ConnexionInconnue},
	}
	for i, c := range cas {
		if got := ConnexionDepuis(c.moi, c.err); got != c.attendu {
			t.Errorf("cas %d : %v, attendu %v", i, got, c.attendu)
		}
	}
}

func TestMessagesErreurLisibles(t *testing.T) {
	horsLigne := fmt.Errorf("serveur injoignable : %w", &net.OpError{Op: "dial", Err: errors.New("x")})
	if m := MessageErreur(horsLigne); !strings.Contains(m, "injoignable") || !strings.Contains(m, "reprise") {
		t.Errorf("message hors ligne : %q", m)
	}
	if m := MessageErreur(&api.ErreurServeur{Statut: 403, Message: "Mandat non valide."}); !strings.Contains(m, "mandat") {
		t.Errorf("message 403 : %q", m)
	}
	if m := MessageErreur(errors.New("code invalide")); m != "Code invalide" {
		t.Errorf("majuscule initiale attendue : %q", m)
	}
}

func TestProfils(t *testing.T) {
	ch := ChoixProfils()
	if len(ch) != 4 || ch[0].Nom != string(scan.ProfilDecouverte) || ch[3].Nom != string(scan.ProfilIndustriel) {
		t.Fatalf("profils inattendus : %+v", ch)
	}
	if got := ProfilPreselectionne("", "industriel"); got != "industriel" {
		t.Errorf("proposition du serveur ignorée : %s", got)
	}
	if got := ProfilPreselectionne("approfondi", "industriel"); got != "approfondi" {
		t.Errorf("le choix du poste doit primer : %s", got)
	}
	if got := ProfilPreselectionne("", "--script=exploit"); got != "standard" {
		t.Errorf("un nom inconnu doit retomber sur standard : %s", got)
	}
}

func TestActionsScan(t *testing.T) {
	if ActionDepuis(nil) != ActionLancer ||
		ActionDepuis(&journal.Instantane{Statut: journal.StatutScan}) != ActionPatienter ||
		ActionDepuis(&journal.Instantane{Statut: journal.StatutCollecte}) != ActionTransmettre ||
		ActionDepuis(&journal.Instantane{Statut: journal.StatutTransmis}) != ActionNouveauScan ||
		ActionDepuis(&journal.Instantane{Statut: journal.StatutErreur}) != ActionLancer {
		t.Fatal("bouton principal du scan incorrect")
	}
}

func TestSuiviOutils(t *testing.T) {
	s := NouveauSuivi("osquery", "nuclei")
	s.Noter(outils.Etape{Outil: "osquery", Texte: "Téléchargement", Progression: 40})
	s.Noter(outils.Etape{Outil: "osquery", Texte: "Vérification de la signature", Progression: -1})
	s.Noter(outils.Etape{Outil: "sharphound", Texte: "Téléchargement", Progression: 10})
	if s.Etapes["osquery"].Progression != 40 || s.Etapes["osquery"].Texte != "Vérification de la signature" {
		t.Errorf("progression indéterminée mal gérée : %+v", s.Etapes["osquery"])
	}
	if strings.Join(s.Ordre, ",") != "osquery,nuclei,sharphound" {
		t.Errorf("ordre : %v", s.Ordre)
	}
}

func TestDivers(t *testing.T) {
	if dateFr("2027-02-06") != "06/02/2027" || dateFr("2027-02-06T23:59:59Z") != "06/02/2027" || dateFr("?") != "?" {
		t.Error("dateFr")
	}
	if !NoteValide("A") || NoteValide("F") || NoteValide("") {
		t.Error("NoteValide")
	}
	if NomAffiche("nmap") != "Nmap" || NomAffiche("auto-test") != "Auto-test (127.0.0.1)" {
		t.Error("NomAffiche")
	}
}

// ----------------------------------------------------------------------------- agent simulé

// agentFactice : satisfait l'interface Agent sans réseau ni outillage (tests et captures).
type agentFactice struct {
	c      app.Contexte
	profil string
	demo   bool
	purge  bool
	etats  []outils.EtatOutil
}

func (f *agentFactice) Contexte() app.Contexte { return f.c }
func (f *agentFactice) Relier(string) error    { f.c.Relie = true; return nil }
func (f *agentFactice) Verifier() (*api.Moi, error) {
	return &api.Moi{MandatValide: true, MandatFin: "2027-02-06", Politique: scan.Politique{Profil: "standard"}}, nil
}
func (f *agentFactice) Lancer(context.Context) error { return nil }
func (f *agentFactice) Transmettre() (*api.Bilan, error) {
	return &api.Bilan{Note: "D", Score: 41, Constats: 12}, nil
}
func (f *agentFactice) Oublier() error { f.c = app.Contexte{}; return nil }
func (f *agentFactice) InstallerOutillageEtAttendre(context.Context, func(outils.Etape)) (*outils.Rapport, error) {
	return &outils.Rapport{Pret: true}, nil
}
func (f *agentFactice) EtatOutils() ([]outils.EtatOutil, error) { return f.etats, nil }
func (f *agentFactice) InstallerNmap(context.Context) error     { return nil }
func (f *agentFactice) OuvrirNpcap() error                      { return nil }
func (f *agentFactice) DefinirProfil(n string) error            { f.profil = n; return nil }
func (f *agentFactice) Profil() string                          { return f.profil }
func (f *agentFactice) DefinirDemo(d bool) error                { f.demo = d; return nil }
func (f *agentFactice) Demo() bool                              { return f.demo }
func (f *agentFactice) Serveur() string {
	return "https://xqecfhmrzrqbpcxjcgmm.supabase.co/functions/v1"
}
func (f *agentFactice) DossierDonnees() string  { return `C:\ProgramData\CACyber\Agent` }
func (f *agentFactice) DossierJournaux() string { return `C:\ProgramData\CACyber\Agent\journaux` }
func (f *agentFactice) Purger(bool) error       { f.purge = true; return nil }

var _ Agent = (*agentFactice)(nil)

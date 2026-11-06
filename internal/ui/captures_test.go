package ui

import (
	"context"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"cacyber/agent/internal/app"
	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
)

// Construit chaque écran avec le pilote de test de Fyne (rendu logiciel, sans fenêtre à l'écran)
// pour vérifier qu'aucun ne plante. Si CACYBER_CAPTURES désigne un dossier, chaque écran y est
// enregistré en PNG (contrôle visuel de la charte).
func TestEcransEtCaptures(t *testing.T) {
	a := test.NewTempApp(t)
	a.Settings().SetTheme(themeCACyber{})
	dossier := os.Getenv("CACYBER_CAPTURES")

	journalScan := []journal.Ligne{
		{Heure: "15:43:08", Type: "info", Texte: "Scan autorisé par le mandat MAND-552100554-2026-01. Lecture seule : aucune intrusion, aucune exploitation."},
		{Heure: "15:43:08", Type: "info", Texte: "Profil de scan : Standard (25 ports examinés)."},
		{Heure: "15:43:09", Type: "info", Texte: "Réseau 10.10.2.0/24 : 9 machines trouvées."},
		{Heure: "15:43:10", Type: "constat", Texte: "SRV-USINE (10.10.2.5) : ports 80, 135, 139, 445, 3389."},
		{Heure: "15:43:12", Type: "ok", Texte: "Collecte terminée : 9 machines, 28 ports ouverts."},
	}
	relie := app.Contexte{Relie: true, Site: "Usine de Brest", SIRET: "55210055400023", Client: "Brest Industrie SAS",
		Cabinet: "Cabinet Durand & Associés", Expire: "2027-02-06", Version: "1.0.0"}
	etats := []outils.EtatOutil{
		{Nom: "nmap", Version: "7.80", Licence: "NPSL", Source: "nmap.org", Signataire: "Insecure.Com LLC", Pret: true, Detail: "installation du poste, signature vérifiée", SHA256: "61f79af8c0ffee"},
		{Nom: "osquery", Version: "5.24.1", Licence: "Apache-2.0", Source: "github.com/osquery", Signataire: "OSQUERY a Series of LF Projects, LLC", Pret: true},
	}
	outillagePret := app.EtatOutillage{Statut: app.OutillagePret, Journal: `C:\ProgramData\CACyber\Agent\journaux\outillage-20261106.log`,
		Rapport: &outils.Rapport{Pret: true, Message: "Moteur de scan prêt.", Tests: []outils.ResultatTest{
			{Outil: "nmap", OK: true, Detail: "mini-scan de 127.0.0.1 réussi (mode connect) : ports 135, 445"},
			{Outil: "osquery", OK: true, Detail: "inventaire en lecture seule opérationnel (5 logiciels lus)"},
			{Outil: "web", OK: true, Detail: "contrôles TLS et en-têtes intégrés opérationnels"},
		}}}

	cas := []struct {
		nom   string
		ecran Ecran
		ctx   app.Contexte
	}{
		{"1-accueil", EcranAccueil, app.Contexte{Version: "1.0.0"}},
		{"2-appairage-saisie", EcranAppairage, app.Contexte{}},
		{"2-appairage-relie", EcranAppairage, relie},
		{"3-outillage", EcranOutillage, func() app.Contexte { c := relie; c.Outillage = outillagePret; return c }()},
		{"4-scan", EcranScan, func() app.Contexte {
			c := relie
			c.Outillage = outillagePret
			c.Mission = &journal.Instantane{Statut: journal.StatutScan, Etape: "Inventaire des postes…", Progression: 55,
				Machines: 9, Ports: 28, Journal: journalScan}
			return c
		}()},
		{"5-resultat", EcranResultat, func() app.Contexte {
			c := relie
			c.Mission = &journal.Instantane{Statut: journal.StatutTransmis, Note: "D", Score: entier(41), Constats: entier(12),
				Message: "Résultats transmis au dossier du cabinet.", Journal: journalScan}
			return c
		}()},
		{"6-parametres", EcranParametres, relie},
	}
	cas = append(cas, struct {
		nom   string
		ecran Ecran
		ctx   app.Contexte
	}{"3b-outillage-chargement-asynchrone", EcranOutillage, relie})
	for _, c := range cas {
		f := &agentFactice{c: c.ctx, etats: etats}
		w := test.NewTempWindow(t, nil)
		ui := Nouvelle(context.Background(), f, Options{Version: "1.0.0"}, w)
		ui.accueilVu = c.ecran != EcranAccueil
		asynchrone := strings.Contains(c.nom, "asynchrone")
		if !asynchrone {
			ui.etatsOutils = etats
		}
		moi, err := f.Verifier()
		ui.connexion, ui.moi = ConnexionDepuis(moi, err), moi
		w.SetContent(ui.Construire())
		w.Resize(fyne.NewSize(1000, 700))
		ui.Afficher(c.ecran)
		if asynchrone { // la liste des composants arrive en arrière-plan : attendre puis contrôler la mise en page
			for i := 0; i < 200 && (ui.chargement || len(ui.etatsOutils) == 0); i++ {
				time.Sleep(10 * time.Millisecond)
			}
			if len(ui.etatsOutils) != len(etats) {
				t.Fatalf("%s : composants non chargés", c.nom)
			}
			time.Sleep(100 * time.Millisecond) // fin du dessin déclenché par le chargement
		}
		ui.Rafraichir()
		if ui.ecran != c.ecran {
			t.Errorf("%s : écran %v affiché, attendu %v", c.nom, ui.ecran, c.ecran)
		}
		if dossier == "" {
			continue
		}
		img := w.Canvas().Capture()
		fichier, err := os.Create(filepath.Join(dossier, c.nom+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if err := png.Encode(fichier, img); err != nil {
			t.Fatal(err)
		}
		_ = fichier.Close()
	}
}

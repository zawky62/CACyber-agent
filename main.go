// CACyber-Agent : agent de scan en LECTURE SEULE, installé chez l'entité contrôlée.
//
// Rôle : relier le poste à un site (code d'appairage émis par le cabinet, mandat signé exigé par
// le serveur), collecter des observations brutes (réseau, inventaire) puis les transmettre au
// cabinet sur un canal mTLS, chaque requête étant signée. Aucune règle d'analyse, aucun score et
// aucune donnée de vulnérabilité ne figurent dans ce programme : c'est le serveur qui analyse.
//
// Jamais : exploitation, test d'intrusion, force brute, essai de mot de passe, modification.
//
// Modes :
//   - par défaut : fenêtre de logiciel native (WebView2) affichant l'interface servie en local
//     (127.0.0.1, port aléatoire, jeton de session) ; aucune console, aucun onglet de navigateur ;
//   - --cli      : déroulé complet en console (appairage, scan, transmission), sans interface ;
//   - --demo     : réseau simulé (jeu « Usine de Brest »), appairage et transmission réels.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"cacyber/agent/internal/api"
	"cacyber/agent/internal/app"
	"cacyber/agent/internal/etat"
	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
	"cacyber/agent/internal/ui"
)

// version est renseignée à la compilation : -ldflags "-X main.version=1.0.0".
var version = "dev"

// La fenêtre native (WebView2) et sa boucle de messages doivent rester sur le fil principal.
func init() { runtime.LockOSThread() }

func main() {
	rattacherConsole() // messages visibles si l'agent est lancé depuis un terminal
	if err := executer(); err != nil {
		fmt.Fprintln(os.Stderr, "Erreur :", err)
		alerte("CACyber — Agent de scan", "Erreur : "+err.Error()) // double-clic : boîte de dialogue
		os.Exit(1)
	}
}

func executer() error {
	var (
		serveur      = flag.String("serveur", "http://localhost:8000", "adresse de la plateforme CACyber (appairage)")
		code         = flag.String("code", "", "code d'appairage CACC-XXXX-XXXX-XXXX-XXXX (appairage non interactif)")
		demo         = flag.Bool("demo", false, "mode démonstration : réseau simulé, appairage et transmission réels")
		cli          = flag.Bool("cli", false, "mode console, sans interface graphique")
		nmap         = flag.String("nmap", "", "chemin de nmap(.exe) ; par défaut recherché sur le poste")
		caFichier    = flag.String("ca", "", "certificat de l'autorité du serveur à épingler (PEM)")
		donnees      = flag.String("donnees", "", "dossier de l'agent (identité, journaux)")
		dev          = flag.Bool("dev", false, "laboratoire : autorise le HTTP non chiffré hors de ce poste")
		afficherVers = flag.Bool("version", false, "affiche la version et quitte")
		reinit       = flag.Bool("reinitialiser", false, "oublie l'appairage de ce poste et quitte")
		instOutils   = flag.Bool("installer-outils", false, "installe et vérifie l'outillage open source (osquery, Nuclei, modèles), exécute l'auto-test et quitte")
		etatOutils   = flag.Bool("etat-outils", false, "contrôle l'outillage installé (empreintes, signatures) sans rien télécharger et quitte")
		instNmap     = flag.Bool("installer-nmap", false, "télécharge l'installateur OFFICIEL de Nmap, le vérifie et l'ouvre en mode interactif (UAC) puis quitte")
		npcap        = flag.Bool("npcap", false, "ouvre la page officielle de Npcap (option des scans avancés SYN/OS) puis quitte")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "CACyber-Agent %s — agent de scan en lecture seule\n\nOptions :\n", version)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *afficherVers {
		fmt.Println("CACyber-Agent", version)
		return nil
	}

	racine := *donnees
	if racine == "" {
		racine = etat.DossierParDefaut()
	}
	d, err := etat.Ouvrir(racine)
	if err != nil {
		return err
	}
	if *reinit {
		if err := d.Oublier(); err != nil {
			return err
		}
		fmt.Println("Appairage oublié :", racine)
		return nil
	}
	u, err := api.VerifierURLServeur(*serveur, *dev)
	if err != nil {
		return err
	}
	var ca []byte
	if *caFichier != "" {
		if ca, err = os.ReadFile(*caFichier); err != nil {
			return fmt.Errorf("lecture de --ca : %w", err)
		}
	}
	a, err := app.Nouvelle(app.Options{Serveur: u, Demo: *demo, Dev: *dev, Nmap: *nmap, CAEpinglee: ca, Version: version}, d)
	if err != nil {
		return err
	}
	ctx, arreter := signal.NotifyContext(context.Background(), os.Interrupt)
	defer arreter()

	if *instOutils || *etatOutils || *instNmap || *npcap {
		return commandesOutillage(ctx, a, *instOutils, *etatOutils, *instNmap, *npcap)
	}

	if *code != "" && !a.Relie() {
		if err := a.Relier(*code); err != nil {
			return fmt.Errorf("appairage : %w", err)
		}
	}
	if *cli {
		return modeConsole(ctx, a, racine)
	}
	return modeInterface(ctx, a, racine)
}

// modeInterface ouvre l'agent comme un logiciel : fenêtre native qui affiche l'interface locale.
// Fermer la fenêtre arrête l'agent. Repli : navigateur (si aucune fenêtre native n'est possible).
func modeInterface(ctx context.Context, a *app.App, racine string) error {
	url, srv, err := ui.Demarrer(ctx, a)
	if err != nil {
		return err
	}
	defer func() {
		fin, annuler := context.WithTimeout(context.Background(), 3*time.Second)
		defer annuler()
		_ = srv.Shutdown(fin)
	}()
	if ui.OuvrirFenetre(url, racine) {
		return nil // la fenêtre a été fermée par l'utilisateur
	}
	fmt.Println("CACyber-Agent", version, "— interface locale :", url)
	fmt.Println("Laissez cette fenêtre ouverte pendant le scan ; Ctrl+C pour quitter.")
	if err := ui.OuvrirNavigateur(url); err != nil {
		fmt.Println("Ouvrez l'adresse ci-dessus dans votre navigateur.")
	}
	<-ctx.Done()
	return nil
}

// commandesOutillage : mise en place et contrôle de l'outillage open source (brief §12.2).
func commandesOutillage(ctx context.Context, a *app.App, installer, controler, nmap, npcap bool) error {
	if nmap {
		fmt.Println("Nmap (licence NPSL, libre et gratuit) : téléchargement de l'installateur officiel depuis nmap.org…")
		if err := a.InstallerNmap(ctx); err != nil {
			return err
		}
		fmt.Println("Installateur vérifié (SHA-256 + signature « Nmap Software LLC ») et ouvert. Acceptez la fenêtre Windows")
		fmt.Println("si vous souhaitez installer Nmap ; Npcap est facultatif (scans avancés). Refuser n'empêche pas l'audit.")
	}
	if npcap {
		fmt.Println("Npcap n'est utile qu'aux scans avancés (SYN, empreinte d'OS). Ouverture de la page officielle :", "https://npcap.com/#download")
		if err := a.OuvrirNpcap(); err != nil {
			return err
		}
	}
	if installer {
		r, err := a.InstallerOutillageEtAttendre(ctx, func(e outils.Etape) {
			if e.Progression >= 0 {
				fmt.Printf("[%-14s] %3d %%  %s\n", e.Outil, e.Progression, e.Texte)
			} else {
				fmt.Printf("[%-14s]        %s\n", e.Outil, e.Texte)
			}
		})
		if r != nil {
			fmt.Println()
			for _, t := range r.Tests {
				fmt.Printf("  %-8s %s  %s\n", t.Outil, map[bool]string{true: "OK   ", false: "ÉCHEC"}[t.OK], t.Detail)
			}
			fmt.Printf("\n%s\nJournal remis au client : %s\n", r.Message, a.Outillage().Journal)
		}
		if err != nil {
			return err
		}
	}
	if controler {
		res, err := a.EtatOutils()
		if err != nil {
			return err
		}
		for _, e := range res {
			fmt.Printf("%-15s %-8s %-6s %s\n", e.Nom, e.Version, map[bool]string{true: "prêt", false: "—"}[e.Pret], e.Detail)
			if e.SHA256 != "" {
				fmt.Printf("%-15s SHA-256 %s%s\n", "", e.SHA256, map[bool]string{true: " · signé « " + e.Signataire + " »", false: ""}[e.Signataire != ""])
			}
		}
	}
	return nil
}

// modeConsole déroule appairage (déjà fait si --code), contrôle du mandat, scan et transmission.
func modeConsole(ctx context.Context, a *app.App, racine string) error {
	if !a.Relie() {
		return errors.New("poste non relié : indiquez --code CACC-XXXX-XXXX-XXXX-XXXX")
	}
	c := a.Contexte()
	fmt.Printf("Site relié : %s — %s (SIRET %s) · %s\n", c.Site, c.Client, c.SIRET, c.Cabinet)
	moi, err := a.Verifier()
	if err != nil {
		return fmt.Errorf("contrôle auprès du serveur (mTLS) : %w", err)
	}
	if !moi.MandatValide {
		return errors.New("aucun mandat signé et valide ne couvre ce site : scan impossible")
	}
	fmt.Printf("Mandat valide jusqu'au %s. Lecture seule.\n", moi.MandatFin)

	// Affichage du journal au fil de l'eau.
	m := a.Mission()
	vu := 0
	afficher := func() {
		j := m.Etat().Journal
		for _, l := range j[vu:] {
			fmt.Printf("%s  %-8s %s\n", l.Heure, "["+l.Type+"]", l.Texte)
		}
		vu = len(j)
	}
	fini := make(chan error, 1)
	go func() { fini <- a.LancerEtAttendre(ctx) }()
	tic := time.NewTicker(300 * time.Millisecond)
	defer tic.Stop()
	for attente := true; attente; {
		select {
		case err = <-fini:
			attente = false
		case <-tic.C:
			afficher()
		}
	}
	afficher()
	if err != nil {
		return err
	}
	if m.Etat().Statut != journal.StatutCollecte {
		return errors.New("collecte interrompue")
	}
	bilan, err := a.Transmettre()
	afficher()
	if err != nil {
		return err
	}
	fmt.Printf("\nRésultat : note %s — score %d/100 — %d constats.\n%s\nJournal local : %s\n",
		bilan.Note, bilan.Score, bilan.Constats, bilan.Message, strings.TrimSpace(racine)+string(os.PathSeparator)+"journaux")
	return nil
}

package ui

// Les six écrans de l'agent : accueil (cadre légal), appairage, outillage, scan, résultat,
// paramètres. Chaque écran est reprenable : il se reconstruit à partir de l'état de l'agent.

import (
	"errors"
	"fmt"
	"image/color"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"cacyber/agent/internal/app"
	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
)

// ----------------------------------------------------------------------------- 1. accueil

func (ui *Interface) ecranAccueil() fyne.CanvasObject {
	logo := canvas.NewImageFromResource(ressourceLogoEncre)
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(58, 64))
	engagements := []string{
		"Lecture seule : découverte du réseau, inventaire, correctifs manquants, configurations à risque.",
		"Jamais d'exploitation, d'intrusion, de force brute, d'essai de mot de passe ni de modification.",
		"Autorisé par un mandat signé : le serveur du cabinet le vérifie avant tout scan.",
		"Tout est journalisé ; le journal lisible et la copie exacte des données transmises vous sont remis.",
	}
	liste := container.NewVBox()
	for _, t := range engagements {
		ic := widget.NewIcon(theme.ConfirmIcon())
		liste.Add(container.NewBorder(nil, nil, container.NewVBox(ic), nil, paragraphe(t)))
	}
	commencer := widget.NewButtonWithIcon("Commencer", theme.NavigateNextIcon(), func() {
		ui.accueilVu = true
		ui.Afficher(EcranConseille(ui.contexte, true))
	})
	commencer.Importance = widget.HighImportance
	objets := []fyne.CanvasObject{
		container.NewHBox(logo, container.NewVBox(layout.NewSpacer(), titre("Audit de cybersécurité autorisé"),
			texteDiscret("CACyber — agent du commissaire aux comptes et de l'expert-comptable"), layout.NewSpacer())),
		paragraphe("Cet outil réalise, pour votre cabinet, un audit de cybersécurité autorisé de votre réseau. " +
			"Il collecte des observations techniques et les transmet au cabinet, qui les analyse : aucune note n'est calculée sur ce poste."),
		carte(sousTitre("Nos engagements"), liste),
	}
	if ui.contexte.Demo {
		objets = append(objets, carte(widget.NewLabelWithStyle("Mode démonstration actif", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			paragraphe("Le réseau est simulé ; l'appairage et la transmission au cabinet sont réels.")))
	}
	objets = append(objets, container.NewHBox(layout.NewSpacer(), commencer))
	return container.NewVBox(objets...)
}

// ----------------------------------------------------------------------------- 2. appairage

func (ui *Interface) ecranAppairage() fyne.CanvasObject {
	if !ui.contexte.Relie {
		return ui.ecranSaisieCode()
	}
	c := ui.contexte
	statut := widget.NewLabel("")
	statut.Wrapping = fyne.TextWrapWord
	verifier := widget.NewButtonWithIcon("Vérifier le mandat", theme.ViewRefreshIcon(), nil)
	continuer := widget.NewButtonWithIcon("Continuer", theme.NavigateNextIcon(), func() {
		ui.Afficher(EcranConseille(ui.agent.Contexte(), true))
	})
	continuer.Importance = widget.HighImportance
	changer := widget.NewButtonWithIcon("Changer de code", theme.ContentUndoIcon(), func() {
		dialog.ShowConfirm("Changer de code d'appairage",
			"L'identité de ce poste sera effacée. Il faudra saisir un nouveau code fourni par votre cabinet. Continuer ?",
			func(ok bool) {
				if !ok {
					return
				}
				if err := ui.agent.Oublier(); err != nil {
					ui.erreur("Changement de code impossible", err)
					return
				}
				ui.moi, ui.connexion = nil, ConnexionInconnue
				ui.Rafraichir()
				ui.Afficher(EcranAppairage)
			}, ui.fen)
	})
	maj := func() {
		switch {
		case ui.connexion == ConnexionEnLigne && ui.moi != nil:
			statut.SetText("Mandat d'autorisation signé et valide jusqu'au " + dateFr(ui.moi.MandatFin) + ". Le scan est autorisé.")
			statut.Importance = widget.SuccessImportance
		case ui.connexion == ConnexionMandatInvalide:
			statut.SetText("Aucun mandat signé et en cours de validité ne couvre ce site : le scan est impossible. " +
				"Contactez votre cabinet pour faire signer ou renouveler le mandat.")
			statut.Importance = widget.WarningImportance
		case ui.connexion == ConnexionHorsLigne:
			statut.SetText("Hors ligne : le mandat ne peut pas être vérifié pour l'instant. Vérifiez la connexion Internet.")
			statut.Importance = widget.DangerImportance
		default:
			statut.SetText("Vérification du mandat auprès du cabinet…")
			statut.Importance = widget.MediumImportance
		}
		statut.Refresh()
	}
	verifier.OnTapped = func() {
		verifier.Disable()
		ui.connexion = ConnexionInconnue
		maj()
		ui.VerifierServeur(func(err error) {
			verifier.Enable()
			if err != nil && !EstHorsLigne(err) {
				ui.erreur("Vérification impossible", err)
			}
		})
	}
	ui.maj = maj
	maj()
	return container.NewVBox(
		titre("Poste relié"),
		paragraphe("Ce poste est relié au site ci-dessous. Le scan n'est possible que si un mandat signé le couvre."),
		carte(ligneInfo("Site", c.Site), ligneInfo("SIRET", c.SIRET), ligneInfo("Entité", c.Client),
			ligneInfo("Cabinet", c.Cabinet), ligneInfo("Identité valable jusqu'au", dateFr(c.Expire))),
		carte(sousTitre("Mandat d'autorisation"), statut),
		container.NewHBox(changer, layout.NewSpacer(), verifier, continuer),
	)
}

func (ui *Interface) ecranSaisieCode() fyne.CanvasObject {
	saisie := widget.NewEntry()
	saisie.SetPlaceHolder("CACC-XXXX-XXXX-XXXX-XXXX")
	attente := widget.NewProgressBarInfinite()
	attente.Hide()
	relier := widget.NewButtonWithIcon("Relier ce poste", theme.ConfirmIcon(), nil)
	relier.Importance = widget.HighImportance
	relier.OnTapped = func() {
		code := app.NormaliserCode(saisie.Text)
		if !app.FormatCode.MatchString(code) {
			ui.erreur("Code invalide", errors.New("le code attendu a la forme CACC-XXXX-XXXX-XXXX-XXXX (16 caractères, sans O ni I)"))
			return
		}
		relier.Disable()
		saisie.Disable()
		attente.Show()
		go func() {
			err := ui.agent.Relier(code)
			fyne.Do(func() {
				attente.Hide()
				relier.Enable()
				saisie.Enable()
				if err != nil {
					ui.erreur("Appairage refusé", err)
					return
				}
				ui.Rafraichir()
				ui.Afficher(EcranAppairage)
				ui.VerifierServeur(nil)
			})
		}()
	}
	saisie.OnSubmitted = func(string) { relier.OnTapped() }
	return container.NewVBox(
		titre("Relier ce poste au cabinet"),
		paragraphe("Saisissez le code d'appairage communiqué par votre cabinet. Il est à usage unique, valable 72 heures, "+
			"et lié à votre site ainsi qu'au mandat d'autorisation signé. Le serveur le vérifie : sans mandat signé, l'appairage est refusé."),
		carte(sousTitre("Code d'appairage"), saisie, attente, container.NewHBox(layout.NewSpacer(), relier)),
		discret("Une clé propre à ce poste est créée et protégée par Windows ; elle ne quitte jamais l'ordinateur. "+
			"Chaque échange avec le cabinet est chiffré (HTTPS) et signé par cette clé."),
	)
}

// ----------------------------------------------------------------------------- 3. outillage

func (ui *Interface) ecranOutillage() fyne.CanvasObject {
	lignes := container.NewVBox()
	tests := container.NewVBox()
	bandeau := container.NewStack()
	installer := widget.NewButtonWithIcon("Installer et vérifier les outils", theme.DownloadIcon(), nil)
	installer.Importance = widget.HighImportance
	nmap := widget.NewButtonWithIcon("Installer Nmap (officiel)…", theme.DownloadIcon(), func() {
		dialog.ShowConfirm("Installer Nmap",
			"L'installateur OFFICIEL de Nmap (nmap.org, licence libre NPSL) va être téléchargé, vérifié (empreinte SHA-256 et "+
				"signature « Nmap Software LLC ») puis ouvert. Windows demandera une validation administrateur (UAC).\n\n"+
				"Npcap, proposé par l'installateur, est facultatif. Refuser n'empêche pas l'audit.",
			func(ok bool) {
				if !ok {
					return
				}
				go func() {
					err := ui.agent.InstallerNmap(ui.ctx)
					fyne.Do(func() {
						if err != nil {
							ui.erreur("Installation de Nmap", err)
						}
					})
				}()
			}, ui.fen)
	})
	npcap := widget.NewButtonWithIcon("Ouvrir la page officielle de Npcap…", theme.ComputerIcon(), func() {
		dialog.ShowConfirm("Option : scans avancés (Npcap)",
			"Npcap n'est utile qu'aux scans avancés (SYN, empreinte du système). Son installation, depuis npcap.com, "+
				"demande une validation administrateur (fenêtre UAC de Windows).\n\nSans Npcap, l'agent reste en mode « connect » : "+
				"l'audit est complet pour les besoins du cabinet. Ouvrir la page officielle ?",
			func(ok bool) {
				if ok {
					if err := ui.agent.OuvrirNpcap(); err != nil {
						ui.erreur("Npcap", err)
					}
				}
			}, ui.fen)
	})
	continuer := widget.NewButtonWithIcon("Continuer vers le scan", theme.NavigateNextIcon(), func() { ui.Afficher(EcranScan) })

	dessiner := func() {
		lignes.Objects = nil
		if ui.chargement && len(ui.etatsOutils) == 0 {
			lignes.Add(discret("Contrôle des composants installés (empreintes et signatures)…"))
		}
		nmapPret := false
		for _, e := range ui.etatsOutils {
			if e.Nom == "nmap" && e.Pret {
				nmapPret = true
			}
		}
		noms := map[string]bool{}
		for _, e := range ui.etatsOutils {
			noms[e.Nom] = true
			lignes.Add(ui.ligneOutil(e))
		}
		if ui.suivi != nil {
			for _, n := range ui.suivi.Ordre {
				if !noms[n] {
					lignes.Add(ui.ligneOutil(outils.EtatOutil{Nom: n}))
				}
			}
		}
		lignes.Refresh()
		if ui.installation {
			installer.Disable()
		} else {
			installer.Enable()
		}
		if nmapPret || ui.installation {
			nmap.Hide()
		} else {
			nmap.Show()
		}
		tests.Objects = nil
		o := ui.contexte.Outillage
		if o.Rapport != nil {
			for _, t := range o.Rapport.Tests {
				ic := widget.NewIcon(theme.ConfirmIcon())
				if !t.OK {
					ic = widget.NewIcon(theme.ErrorIcon())
				}
				l := paragraphe(NomAffiche(t.Outil) + " — " + t.Detail)
				tests.Add(container.NewBorder(nil, nil, container.NewVBox(ic), nil, l))
			}
			if o.Journal != "" {
				tests.Add(discret("Journal remis au client : " + o.Journal))
			}
		} else if !ui.installation {
			tests.Add(discret("L'auto-test s'exécute à la fin de la mise en place : mini-scan de ce poste (127.0.0.1), inventaire en lecture seule, validation des modèles."))
		}
		tests.Refresh()
		bandeau.Objects = nil
		switch {
		case o.Rapport != nil && o.Rapport.Pret && o.Statut == app.OutillagePret:
			bandeau.Add(carteCouleur(CouleurVert, "Moteur de scan prêt", o.Rapport.Message))
		case o.Statut == app.OutillageErreur:
			bandeau.Add(carteCouleur(CouleurRouge, "Mise en place incomplète", o.Message+" L'étape peut être relancée."))
		case ui.installation:
			bandeau.Add(carteCouleur(CouleurBleu, "Mise en place en cours…", o.Etape))
		}
		bandeau.Refresh()
		ui.RemettreEnPage()
	}
	installer.OnTapped = func() {
		if ui.installation {
			return
		}
		ui.installation = true
		var noms []string
		for _, e := range ui.etatsOutils {
			noms = append(noms, e.Nom)
		}
		ui.suivi = NouveauSuivi(noms...)
		dessiner()
		go func() {
			_, err := ui.agent.InstallerOutillageEtAttendre(ui.ctx, func(e outils.Etape) {
				fyne.Do(func() {
					if ui.suivi != nil {
						ui.suivi.Noter(e)
					}
					if ui.ecran == EcranOutillage {
						dessiner()
					}
				})
			})
			etats, errE := ui.agent.EtatOutils()
			fyne.Do(func() {
				ui.installation = false
				if errE == nil {
					ui.etatsOutils = etats
				}
				ui.Rafraichir()
				if ui.ecran == EcranOutillage {
					dessiner()
				}
				if err != nil {
					ui.erreur("Outillage", err)
				}
			})
		}()
	}
	ui.maj = func() {
		if ui.installation {
			dessiner()
		}
	}
	dessiner()
	// Chargement de l'état des composants APRÈS le premier affichage (contrôle des signatures : quelques secondes).
	if len(ui.etatsOutils) == 0 && !ui.chargement {
		ui.chargement = true
		go func() {
			etats, err := ui.agent.EtatOutils()
			fyne.Do(func() {
				ui.chargement = false
				if err == nil {
					ui.etatsOutils = etats
				}
				if ui.ecran == EcranOutillage {
					dessiner()
				}
			})
		}()
	}
	return container.NewVBox(
		titre("Mise en place de l'outillage"),
		paragraphe("Composants libres et gratuits, téléchargés depuis leurs sources officielles et vérifiés (empreinte SHA-256, "+
			"signature de l'éditeur) avant chaque exécution. Aucun droit administrateur n'est nécessaire : Nmap fonctionne en mode « connect »."),
		bandeau,
		carte(sousTitre("Composants"), lignes, container.NewHBox(nmap, layout.NewSpacer(), installer)),
		modulesIntegres(),
		carte(sousTitre("Auto-test de bon fonctionnement"), tests),
		carte(sousTitre("Option : scans avancés (Npcap)"),
			discret("Facultatif. Utile seulement pour les scans SYN et l'empreinte du système ; demande une validation administrateur (UAC)."),
			container.NewHBox(npcap)),
		container.NewHBox(layout.NewSpacer(), continuer),
	)
}

// ligneOutil : composant, version, statut, détail et (pendant l'installation) barre de progression.
func (ui *Interface) ligneOutil(e outils.EtatOutil) fyne.CanvasObject {
	nom := widget.NewLabelWithStyle(NomAffiche(e.Nom), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	version := discret(strings.TrimSpace(e.Version + "  " + e.Licence))
	var statut fyne.CanvasObject
	switch {
	case e.Pret:
		statut = pastilleTexte("Prêt", CouleurVert)
	case e.Version == "" && e.Detail == "":
		statut = pastilleTexte("À installer", CouleurAmbre)
	default:
		statut = pastilleTexte("À vérifier", CouleurAmbre)
	}
	var morceaux []string
	if strings.TrimSpace(e.Detail) != "" {
		morceaux = append(morceaux, strings.TrimSpace(e.Detail))
	}
	if e.Signataire != "" {
		morceaux = append(morceaux, "signé « "+e.Signataire+" »")
	}
	detail := discret(strings.Join(morceaux, " · "))
	objets := []fyne.CanvasObject{container.NewBorder(nil, nil, container.NewHBox(nom, version), container.NewCenter(statut))}
	if e.Detail != "" || e.Signataire != "" {
		objets = append(objets, detail)
	}
	if ui.installation && ui.suivi != nil {
		if et, ok := ui.suivi.Etapes[e.Nom]; ok {
			b := widget.NewProgressBar()
			b.SetValue(float64(et.Progression) / 100)
			objets = append(objets, b, discret(et.Texte))
		}
	}
	objets = append(objets, widget.NewSeparator())
	return container.NewVBox(objets...)
}

// carteCouleur : bandeau de statut (vert, rouge, bleu).
func carteCouleur(c color.Color, titreTexte, texte string) fyne.CanvasObject {
	fond := canvas.NewRectangle(c)
	fond.CornerRadius = 10
	t := canvas.NewText(titreTexte, color.White)
	t.TextStyle = fyne.TextStyle{Bold: true}
	t.TextSize = 16
	boite := container.NewVBox(t)
	if n := strings.TrimRight(strings.TrimSpace(texte), "."); n != "" && n != strings.TrimRight(titreTexte, ".…") {
		l := widget.NewRichText(&widget.TextSegment{Text: texte, Style: widget.RichTextStyle{ColorName: theme.ColorNameForegroundOnPrimary}})
		l.Wrapping = fyne.TextWrapWord
		boite.Add(l)
	}
	return container.NewStack(fond, container.NewPadded(container.NewPadded(boite)))
}

// ----------------------------------------------------------------------------- 4. scan

func (ui *Interface) ecranScan() fyne.CanvasObject {
	choix := ChoixProfils()
	var libelles []string
	for _, p := range choix {
		libelles = append(libelles, p.Libelle)
	}
	description := discret("")
	selection := widget.NewSelect(libelles, nil)
	profilServeur := ""
	if ui.moi != nil {
		profilServeur = ui.moi.Politique.Profil
	}
	pre := ProfilPreselectionne(ui.agent.Profil(), profilServeur)
	for _, p := range choix {
		if p.Nom == pre {
			selection.SetSelected(p.Libelle)
			description.SetText(p.Description)
		}
	}
	selection.OnChanged = func(l string) {
		for _, p := range choix {
			if p.Libelle == l {
				description.SetText(p.Description)
				nom := p.Nom
				if nom == ProfilPreselectionne("", profilServeur) {
					nom = "" // retour à la proposition du cabinet
				}
				if err := ui.agent.DefinirProfil(nom); err != nil {
					ui.erreur("Profil de scan", err)
				}
			}
		}
	}
	demo := widget.NewCheck("Mode démonstration (réseau simulé, transmission réelle)", nil)
	demo.SetChecked(ui.agent.Demo())
	demo.OnChanged = func(v bool) {
		if err := ui.agent.DefinirDemo(v); err != nil {
			ui.erreur("Mode démonstration", err)
			demo.SetChecked(!v)
		}
		ui.Rafraichir()
	}
	barre := widget.NewProgressBar()
	etape := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	compteurs := discret("")
	probleme := widget.NewLabel("")
	probleme.Wrapping = fyne.TextWrapWord
	probleme.Importance = widget.DangerImportance
	probleme.Hide()
	var lignes []journal.Ligne
	liste := widget.NewList(func() int { return len(lignes) },
		func() fyne.CanvasObject {
			h := widget.NewLabel("00:00:00")
			h.Importance = widget.LowImportance
			t := widget.NewLabel("")
			t.Truncation = fyne.TextTruncateEllipsis
			return container.NewBorder(nil, nil, container.NewHBox(h, etiquetteJournal("info")), nil, t)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(lignes) {
				return
			}
			l := lignes[i]
			b := o.(*fyne.Container)
			b.Objects[0].(*widget.Label).SetText(l.Texte)
			gauche := b.Objects[1].(*fyne.Container)
			gauche.Objects[0].(*widget.Label).SetText(l.Heure)
			gauche.Objects[1] = etiquetteJournal(l.Type)
			gauche.Refresh()
		})
	hauteur := canvas.NewRectangle(color.Transparent)
	hauteur.SetMinSize(fyne.NewSize(1, 270))
	cadreJournal := container.NewStack(hauteur, liste)
	action := widget.NewButtonWithIcon("Lancer le scan", theme.MediaPlayIcon(), nil)
	action.Importance = widget.HighImportance

	maj := func() {
		m := ui.contexte.Mission
		a := ActionDepuis(m)
		switch a {
		case ActionLancer:
			action.SetText("Lancer le scan")
			action.SetIcon(theme.MediaPlayIcon())
			action.Enable()
		case ActionPatienter:
			action.SetText("Scan en cours…")
			action.Disable()
		case ActionTransmettre:
			action.SetText("Transmettre au cabinet")
			action.SetIcon(theme.UploadIcon())
			action.Enable()
		case ActionNouveauScan:
			action.SetText("Nouveau scan")
			action.SetIcon(theme.ViewRefreshIcon())
			action.Enable()
		}
		if a == ActionPatienter {
			selection.Disable()
			demo.Disable()
		} else {
			selection.Enable()
			demo.Enable()
		}
		if m == nil {
			return
		}
		barre.SetValue(float64(m.Progression) / 100)
		etape.SetText(m.Etape)
		if m.Machines > 0 || m.Ports > 0 {
			compteurs.SetText(fmt.Sprintf("%d machine(s) · %d port(s) ouvert(s)", m.Machines, m.Ports))
		}
		if m.Statut == journal.StatutErreur && m.Message != "" {
			probleme.SetText("Scan interrompu : " + m.Message + " — l'étape peut être relancée.")
			probleme.Show()
		} else {
			probleme.Hide()
		}
		if len(m.Journal) != len(lignes) {
			lignes = m.Journal
			liste.Refresh()
			liste.ScrollToBottom()
		}
	}
	action.OnTapped = func() {
		switch ActionDepuis(ui.contexte.Mission) {
		case ActionLancer, ActionNouveauScan:
			if ui.connexion == ConnexionMandatInvalide {
				ui.message("Scan impossible", "Aucun mandat signé et en cours de validité ne couvre ce site. Contactez votre cabinet.", theme.WarningIcon())
				return
			}
			if err := ui.agent.Lancer(ui.ctx); err != nil {
				ui.erreur("Scan", err)
			}
			ui.Rafraichir()
		case ActionTransmettre:
			action.Disable()
			go func() {
				_, err := ui.agent.Transmettre()
				fyne.Do(func() {
					ui.Rafraichir()
					if err != nil {
						ui.erreur("Transmission refusée", err)
						return
					}
					ui.Afficher(EcranResultat)
				})
			}()
		}
	}
	ui.maj = maj
	maj()
	c := ui.contexte
	return container.NewVBox(
		titre("Scan du réseau"),
		paragraphe(fmt.Sprintf("Site : %s — %s. Seules les plages autorisées par le mandat sont examinées, en lecture seule.", c.Site, c.Client)),
		carte(sousTitre("Profil de scan"), selection, description, demo),
		carte(container.NewBorder(nil, nil, nil, action, etape), barre, compteurs, probleme),
		carte(sousTitre("Journal du scan"), cadreJournal,
			discret("Ce journal est conservé sur le poste ("+ui.agent.DossierJournaux()+") et remis au client.")),
	)
}

// etiquetteJournal : étiquette de type, de taille fixe et centrée verticalement dans la ligne.
func etiquetteJournal(t string) fyne.CanvasObject {
	return container.NewCenter(container.NewGridWrap(fyne.NewSize(72, 22), pastilleTexte(libelleType(t), couleurType(t))))
}

func libelleType(t string) string {
	switch t {
	case "ok":
		return "ok"
	case "constat":
		return "constat"
	case "critique":
		return "critique"
	case "erreur":
		return "erreur"
	default:
		return "info"
	}
}

func couleurType(t string) color.Color {
	switch t {
	case "ok":
		return CouleurVert
	case "constat":
		return CouleurAmbre
	case "critique", "erreur":
		return CouleurRouge
	default:
		return CouleurBleu
	}
}

// ----------------------------------------------------------------------------- 5. résultat

func (ui *Interface) ecranResultat() fyne.CanvasObject {
	m := ui.contexte.Mission
	if m == nil || m.Statut != journal.StatutTransmis {
		return container.NewVBox(titre("Résultat"), paragraphe("Aucun résultat transmis pour l'instant."))
	}
	score, constats := "—", "—"
	if m.Score != nil {
		score = fmt.Sprintf("%d / 100", *m.Score)
	}
	if m.Constats != nil {
		constats = fmt.Sprintf("%d", *m.Constats)
	}
	ouvrir := widget.NewButtonWithIcon("Ouvrir le journal local", theme.FolderOpenIcon(), func() {
		if err := ouvrirDossier(ui.agent.DossierJournaux()); err != nil {
			ui.erreur("Journal local", err)
		}
	})
	nouveau := widget.NewButtonWithIcon("Nouveau scan", theme.ViewRefreshIcon(), func() { ui.Afficher(EcranScan) })
	nouveau.Importance = widget.HighImportance
	libelleNote := widget.NewLabelWithStyle("Note cyber "+m.Note, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	message := m.Message
	if message == "" {
		message = "Résultats transmis au dossier du cabinet."
	}
	return container.NewVBox(
		titre("Résultats transmis"),
		carte(container.NewHBox(badgeNote(m.Note, 104),
			container.NewVBox(layout.NewSpacer(), libelleNote, ligneInfo("Score", score), ligneInfo("Constats", constats), layout.NewSpacer()))),
		carteCouleur(CouleurVert, "Résultats transmis", message),
		ui.carteAnnuaire(m),
		paragraphe("L'analyse et la note sont établies par le serveur du cabinet à partir des observations transmises. "+
			"Votre cabinet vous communiquera ses constats et recommandations. Une copie exacte des données transmises est conservée sur ce poste."),
		container.NewHBox(ouvrir, layout.NewSpacer(), nouveau),
	)
}

// ----------------------------------------------------------------------------- 6. paramètres

func (ui *Interface) ecranParametres() fyne.CanvasObject {
	c := ui.contexte
	composants := container.NewVBox(discret("Contrôle des composants…"))
	go func() {
		etats, err := ui.agent.EtatOutils()
		fyne.Do(func() {
			composants.Objects = nil
			if err != nil {
				composants.Add(discret("Contrôle impossible : " + MessageErreur(err)))
			}
			for _, e := range etats {
				lib := fmt.Sprintf("%s %s — %s", NomAffiche(e.Nom), e.Version, valeur(e.Licence, "licence libre"))
				det := e.Source
				if e.Signataire != "" {
					det += " · signé « " + e.Signataire + " »"
				}
				if e.SHA256 != "" {
					det += " · SHA-256 " + e.SHA256[:min(16, len(e.SHA256))] + "…"
				}
				composants.Add(widget.NewLabelWithStyle(lib, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
				composants.Add(discret(det))
			}
			composants.Refresh()
			if ui.ecran == EcranParametres {
				ui.RemettreEnPage()
			}
		})
	}()
	avecJournaux := widget.NewCheck("Effacer aussi les journaux remis au client", nil)
	purger := widget.NewButtonWithIcon("Purger les données locales…", theme.DeleteIcon(), func() {
		texte := "Seront effacés : l'identité de ce poste (clé, appairage) et l'outillage installé."
		if avecJournaux.Checked {
			texte += " Les journaux remis au client seront AUSSI effacés."
		} else {
			texte += " Les journaux remis au client sont conservés."
		}
		dialog.ShowConfirm("Désinstaller l'agent", texte+"\n\nCette action est définitive. Continuer ?", func(ok bool) {
			if !ok {
				return
			}
			if err := ui.agent.Purger(avecJournaux.Checked); err != nil {
				ui.erreur("Purge incomplète", err)
				return
			}
			_ = purgerPreferences()
			d := dialog.NewInformation("Données effacées",
				"Les données locales de l'agent ont été effacées. Rien d'autre n'est installé sur ce poste : "+
					"vous pouvez supprimer le fichier CACyber-Agent.exe.", ui.fen)
			d.SetOnClosed(func() { fyne.CurrentApp().Quit() })
			d.Show()
		}, ui.fen)
	})
	purger.Importance = widget.DangerImportance
	ouvrir := widget.NewButtonWithIcon("Ouvrir le dossier des journaux", theme.FolderOpenIcon(), func() {
		if err := ouvrirDossier(ui.agent.DossierJournaux()); err != nil {
			ui.erreur("Journal local", err)
		}
	})
	site := "non relié"
	if c.Relie {
		site = c.Site + " — " + c.Client + " (" + c.Cabinet + ")"
	}
	return container.NewVBox(
		titre("Paramètres et à propos"),
		carte(sousTitre("Agent"), ligneInfo("Version", ui.opt.Version), ligneInfo("Plateforme", ui.agent.Serveur()),
			ligneInfo("Site relié", site), ligneInfo("Données de l'agent", ui.agent.DossierDonnees()),
			ligneInfo("Journaux du client", ui.agent.DossierJournaux()), container.NewHBox(ouvrir)),
		carte(sousTitre("Composants open source et licences"), composants,
			discret("Tous les composants sont libres et gratuits ; leurs textes de licence sont conservés avec chaque outil installé. "+
				"L'agent CACyber est lui-même un logiciel à code source ouvert.")),
		carte(sousTitre("Désinstallation"),
			paragraphe("L'agent est un exécutable unique : il n'installe ni service ni pilote. La purge efface ses données locales ; "+
				"le cabinet peut en outre révoquer ce poste depuis sa console."),
			avecJournaux, container.NewHBox(purger)),
	)
}

func valeur(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// modulesIntegres : contrôles réalisés par le code de l'agent lui-même (rien à télécharger, rien à
// signer en plus : ils font partie de l'exécutable CACyber). Affichés pour que l'utilisateur sache
// exactement ce qui sera examiné, en lecture seule.
func modulesIntegres() fyne.CanvasObject {
	domaine := strings.TrimSpace(os.Getenv("USERDNSDOMAIN"))
	ad := "Poste hors domaine Active Directory : collecte non applicable ici."
	if domaine != "" {
		ad = "Poste membre du domaine " + domaine + " : collecte possible (LDAP chiffré, lecture seule)."
	}
	ligne := func(nom, detail string) fyne.CanvasObject {
		return container.NewVBox(
			widget.NewLabelWithStyle(nom, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			discret(detail),
		)
	}
	return carte(sousTitre("Modules d'audit intégrés (inclus dans l'agent)"),
		ligne("Active Directory — chemins d'attaque façon BloodHound",
			"Comptes, groupes, délégations et droits (ACL) lus en LDAP ; les chemins vers les administrateurs du domaine "+
				"sont calculés par le serveur CACyber. "+ad),
		ligne("Contrôles web et TLS",
			"Certificats, versions TLS et chiffrements faibles, en-têtes de sécurité, technologies annoncées."),
		ligne("Inventaire authentifié WinRM / SSH",
			"Logiciels, correctifs, pare-feu, chiffrement des postes, avec les identifiants fournis par l'entité "+
				"(gardés en mémoire, jamais enregistrés)."),
		ligne("Scripts Nmap (liste blanche « safe »)",
			"banner, nbstat, smb-protocols, smb2-security-mode, smb-os-discovery, ftp-anon, rdp-enum-encryption, "+
				"ssh2-enum-algos, http-title, http-auth. Jamais de script intrusif, d'attaque ou de force brute."),
	)
}

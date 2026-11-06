package ui

// Fenêtre native de l'agent (Fyne) : en-tête aux couleurs de CACyber avec l'état de la connexion,
// navigation par étapes à gauche, écran courant à droite. L'état de l'agent est relu deux fois par
// seconde (sans réseau) ; le mandat est revérifié auprès du serveur toutes les 30 secondes.
//
// Règle Fyne : toute mise à jour de l'interface depuis une goroutine passe par fyne.Do.

import (
	"context"
	"fmt"
	"image/color"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"cacyber/agent/internal/api"
	"cacyber/agent/internal/app"
	"cacyber/agent/internal/outils"
)

// IdentifiantApplication : identifiant Fyne (préférences propres à l'agent, purgées à la désinstallation).
const IdentifiantApplication = "fr.cacyber.agent"

// Options d'affichage.
type Options struct {
	Version string
}

// Interface : état de la fenêtre (manipulé uniquement sur le fil de l'interface).
type Interface struct {
	agent Agent
	ctx   context.Context
	opt   Options
	fen   fyne.Window

	ecran     Ecran
	accueilVu bool
	contexte  app.Contexte

	// Liaison avec le serveur.
	connexion    Connexion
	moi          *api.Moi
	verifEnCours atomic.Bool

	// Outillage.
	installation bool
	suivi        *SuiviOutils
	etatsOutils  []outils.EtatOutil
	chargement   bool

	// Éléments permanents.
	contenu    *fyne.Container
	navigation map[Ecran]*widget.Button
	pastille   *canvas.Circle
	texteLien  *canvas.Text
	blocLien   *fyne.Container
	bandeau    *fyne.Container

	// Mise à jour en direct de l'écran courant (remplacée à chaque changement d'écran).
	maj func()
	// Défilement de l'écran courant (nouvelle mise en page après une mise à jour asynchrone).
	defilement *container.Scroll
}

// Lancer ouvre la fenêtre et BLOQUE jusqu'à sa fermeture (fil principal requis).
func Lancer(ctx context.Context, a Agent, opt Options) error {
	ap := fyneapp.NewWithID(IdentifiantApplication)
	ap.Settings().SetTheme(themeCACyber{})
	ap.SetIcon(ressourceIcone)
	fen := ap.NewWindow("CACyber — Agent d'audit")
	fen.SetIcon(ressourceIcone)
	ctx, arreter := context.WithCancel(ctx)
	defer arreter()
	ui := Nouvelle(ctx, a, opt, fen)
	fen.SetContent(ui.Construire())
	fen.Resize(fyne.NewSize(1000, 700))
	fen.CenterOnScreen()
	fen.SetOnClosed(arreter)
	go ui.boucle()
	go func() { // Ctrl+C dans un terminal : fermeture propre
		<-ctx.Done()
		fyne.Do(func() { ap.Quit() })
	}()
	fen.ShowAndRun()
	return nil
}

// Nouvelle prépare l'interface (sans l'afficher) : utilisée par Lancer et par les tests.
func Nouvelle(ctx context.Context, a Agent, opt Options, fen fyne.Window) *Interface {
	ui := &Interface{agent: a, ctx: ctx, opt: opt, fen: fen, navigation: map[Ecran]*widget.Button{}}
	ui.contexte = a.Contexte()
	ui.ecran = EcranConseille(ui.contexte, false)
	return ui
}

// Construire assemble l'en-tête, la navigation et la zone d'écran.
func (ui *Interface) Construire() fyne.CanvasObject {
	ui.contenu = container.NewStack()
	corps := container.NewBorder(nil, nil, ui.barreNavigation(), nil, ui.contenu)
	ui.Afficher(ui.ecran)
	return container.NewBorder(ui.entete(), nil, nil, nil, corps)
}

// entete : bandeau encre avec le logo, le nom du produit et l'état de la liaison.
func (ui *Interface) entete() fyne.CanvasObject {
	fond := canvas.NewRectangle(CouleurEncre)
	logo := canvas.NewImageFromResource(ressourceLogoBlanc)
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(30, 34))
	nom := canvas.NewText("CACyber", color.White)
	nom.TextStyle = fyne.TextStyle{Bold: true}
	nom.TextSize = 21
	sous := canvas.NewText("Agent d'audit · lecture seule", CouleurEncre2)
	sous.TextSize = 12
	ui.pastille = canvas.NewCircle(CouleurEncre2)
	pastille := container.NewGridWrap(fyne.NewSize(10, 10), ui.pastille)
	ui.texteLien = canvas.NewText(TexteConnexion(ConnexionInconnue), color.White)
	ui.texteLien.TextSize = 13
	version := canvas.NewText("v"+ui.opt.Version, CouleurEncre2)
	version.TextSize = 12
	gauche := container.NewHBox(logo, container.NewVBox(layout.NewSpacer(), nom, sous, layout.NewSpacer()))
	ecart := canvas.NewRectangle(color.Transparent)
	ecart.SetMinSize(fyne.NewSize(18, 1))
	ui.blocLien = container.NewHBox(container.NewCenter(pastille), container.NewCenter(ui.texteLien), ecart, container.NewCenter(version))
	droite := ui.blocLien
	ui.bandeau = container.NewBorder(nil, nil, gauche, droite)
	return container.NewStack(fond, container.NewPadded(container.NewPadded(ui.bandeau)))
}

// barreNavigation : étapes du parcours (reprenables, accessibles selon l'état).
func (ui *Interface) barreNavigation() fyne.CanvasObject {
	boite := container.NewVBox()
	for i, e := range Parcours {
		e := e
		libelle := fmt.Sprintf("%d   %s", i+1, TitresEcrans[e])
		var b *widget.Button
		if e == EcranParametres {
			b = widget.NewButtonWithIcon(TitresEcrans[e], theme.SettingsIcon(), func() { ui.Afficher(e) })
		} else {
			b = widget.NewButton(libelle, func() { ui.Afficher(e) })
		}
		b.Alignment = widget.ButtonAlignLeading
		ui.navigation[e] = b
		if e == EcranParametres {
			boite.Add(widget.NewSeparator())
		}
		boite.Add(b)
	}
	cadre := canvas.NewRectangle(CouleurCarte)
	cadre.StrokeColor, cadre.StrokeWidth = CouleurBordure, 1
	largeur := canvas.NewRectangle(color.Transparent)
	largeur.SetMinSize(fyne.NewSize(186, 1))
	return container.NewStack(cadre, container.NewPadded(container.NewVBox(largeur, boite)))
}

// Afficher change d'écran (si l'état le permet).
func (ui *Interface) Afficher(e Ecran) {
	if !Accessible(e, ui.contexte) {
		e = EcranConseille(ui.contexte, ui.accueilVu)
	}
	if e != EcranAccueil {
		ui.accueilVu = true
	}
	ui.ecran = e
	var vue fyne.CanvasObject
	ui.maj = nil
	switch e {
	case EcranAccueil:
		vue = ui.ecranAccueil()
	case EcranAppairage:
		vue = ui.ecranAppairage()
	case EcranOutillage:
		vue = ui.ecranOutillage()
	case EcranScan:
		vue = ui.ecranScan()
	case EcranResultat:
		vue = ui.ecranResultat()
	case EcranParametres:
		vue = ui.ecranParametres()
	}
	ui.defilement = container.NewVScroll(container.NewPadded(container.NewPadded(vue)))
	ui.contenu.Objects = []fyne.CanvasObject{ui.defilement}
	ui.contenu.Refresh()
	ui.majNavigation()
}

func (ui *Interface) majNavigation() {
	for e, b := range ui.navigation {
		if e == ui.ecran {
			b.Importance = widget.HighImportance
		} else {
			b.Importance = widget.LowImportance
		}
		if Accessible(e, ui.contexte) {
			b.Enable()
		} else {
			b.Disable()
		}
		b.Refresh()
	}
}

func (ui *Interface) majConnexion() {
	if ui.texteLien == nil {
		return
	}
	c := ui.connexion
	if !ui.contexte.Relie {
		c = ConnexionInconnue
	}
	couleur := map[Connexion]color.Color{
		ConnexionEnLigne: CouleurVert, ConnexionHorsLigne: CouleurRouge, ConnexionMandatInvalide: CouleurAmbre,
	}[c]
	if couleur == nil {
		couleur = CouleurEncre2
	}
	ui.pastille.FillColor = couleur
	ui.pastille.Refresh()
	ui.texteLien.Text = TexteConnexion(c)
	if ui.contexte.Demo {
		ui.texteLien.Text += " · démonstration"
	}
	ui.texteLien.Refresh()
	ui.blocLien.Refresh() // la largeur du texte a changé : nouvelle mise en page du bloc…
	ui.bandeau.Refresh()  // …et de l'en-tête qui le contient
}

// Rafraichir relit l'état de l'agent et met à jour l'écran courant (fil de l'interface).
func (ui *Interface) Rafraichir() {
	ui.contexte = ui.agent.Contexte()
	ui.majNavigation()
	ui.majConnexion()
	if ui.maj != nil {
		ui.maj()
	}
}

// boucle : rafraîchissement local (500 ms) et vérification du mandat auprès du serveur (30 s).
func (ui *Interface) boucle() {
	local := time.NewTicker(500 * time.Millisecond)
	serveur := time.NewTicker(30 * time.Second)
	defer local.Stop()
	defer serveur.Stop()
	ui.VerifierServeur(nil)
	for {
		select {
		case <-ui.ctx.Done():
			return
		case <-local.C:
			fyne.Do(ui.Rafraichir)
		case <-serveur.C:
			ui.VerifierServeur(nil)
		}
	}
}

// VerifierServeur interroge le serveur (requête signée) en arrière-plan ; `ensuite` est appelé sur
// le fil de l'interface avec l'erreur éventuelle.
func (ui *Interface) VerifierServeur(ensuite func(error)) {
	if !ui.agent.Contexte().Relie || !ui.verifEnCours.CompareAndSwap(false, true) {
		if ensuite != nil {
			fyne.Do(func() { ensuite(nil) })
		}
		return
	}
	go func() {
		defer ui.verifEnCours.Store(false)
		moi, err := ui.agent.Verifier()
		fyne.Do(func() {
			ui.connexion = ConnexionDepuis(moi, err)
			if err == nil {
				ui.moi = moi
			}
			ui.Rafraichir()
			if ensuite != nil {
				ensuite(err)
			}
		})
	}()
}

// Remettre en page : après l'ajout ou le retrait d'éléments dans un écran déjà affiché (liste des
// composants chargée en arrière-plan…), chaque conteneur recalcule sa taille, du plus profond au
// défilement, pour qu'aucun bloc ne déborde sur le suivant.
func (ui *Interface) RemettreEnPage() {
	if ui.defilement == nil {
		return
	}
	var parcourir func(o fyne.CanvasObject)
	parcourir = func(o fyne.CanvasObject) {
		if c, ok := o.(*fyne.Container); ok {
			for _, enfant := range c.Objects {
				parcourir(enfant)
			}
			c.Refresh()
		}
	}
	parcourir(ui.defilement.Content)
	ui.defilement.Refresh()
}

// ----------------------------------------------------------------------------- éléments communs

// erreur : boîte de dialogue lisible (message en français, retour à la ligne automatique).
func (ui *Interface) erreur(titre string, err error) {
	if err == nil {
		return
	}
	ui.message(titre, MessageErreur(err), theme.ErrorIcon())
}

func (ui *Interface) message(titre, texte string, icone fyne.Resource) {
	l := widget.NewLabel(texte)
	l.Wrapping = fyne.TextWrapWord
	contenu := container.NewBorder(nil, nil, container.NewVBox(widget.NewIcon(icone)), nil, l)
	d := dialog.NewCustom(titre, "Fermer", container.NewGridWrap(fyne.NewSize(440, 150), contenu), ui.fen)
	d.Show()
}

func titre(t string) fyne.CanvasObject {
	x := canvas.NewText(t, CouleurEncre)
	x.TextStyle = fyne.TextStyle{Bold: true}
	x.TextSize = 24
	return x
}

func sousTitre(t string) fyne.CanvasObject {
	x := canvas.NewText(t, CouleurEncre)
	x.TextStyle = fyne.TextStyle{Bold: true}
	x.TextSize = 16
	return x
}

func paragraphe(t string) *widget.Label {
	l := widget.NewLabel(t)
	l.Wrapping = fyne.TextWrapWord
	return l
}

func discret(t string) *widget.Label {
	l := paragraphe(t)
	l.Importance = widget.LowImportance
	return l
}

// carte : bloc blanc à bord fin et coins arrondis.
func carte(objets ...fyne.CanvasObject) fyne.CanvasObject {
	fond := canvas.NewRectangle(CouleurCarte)
	fond.StrokeColor, fond.StrokeWidth, fond.CornerRadius = CouleurBordure, 1, 10
	return container.NewStack(fond, container.NewPadded(container.NewPadded(container.NewVBox(objets...))))
}

// pastilleTexte : étiquette colorée (statut).
func pastilleTexte(t string, c color.Color) fyne.CanvasObject {
	fond := canvas.NewRectangle(c)
	fond.CornerRadius = 9
	x := canvas.NewText(t, color.White)
	x.TextStyle = fyne.TextStyle{Bold: true}
	x.TextSize = 12
	return container.NewStack(fond, container.New(layout.NewCustomPaddedLayout(3, 3, 9, 9), x))
}

// badgeNote : grande note A→E aux couleurs de la console.
func badgeNote(n string, cote float32) fyne.CanvasObject {
	if !NoteValide(n) {
		n = "?"
	}
	fond := canvas.NewRectangle(CouleurNote(n))
	fond.CornerRadius = cote / 5
	x := canvas.NewText(n, color.White)
	x.TextStyle = fyne.TextStyle{Bold: true}
	x.TextSize = cote * 0.55
	return container.NewGridWrap(fyne.NewSize(cote, cote), container.NewStack(fond, container.NewCenter(x)))
}

// ligneInfo : « Libellé : valeur » sur deux colonnes.
func ligneInfo(libelle, valeur string) fyne.CanvasObject {
	l := widget.NewLabel(libelle)
	l.Importance = widget.LowImportance
	v := widget.NewLabel(valeur)
	v.TextStyle = fyne.TextStyle{Bold: true}
	v.Wrapping = fyne.TextWrapWord
	return container.NewBorder(nil, nil, container.NewGridWrap(fyne.NewSize(200, 34), l), nil, v)
}

// texteDiscret : ligne courte en gris, sans retour à la ligne.
func texteDiscret(t string) fyne.CanvasObject {
	x := canvas.NewText(t, CouleurDiscret)
	x.TextSize = 13
	return x
}

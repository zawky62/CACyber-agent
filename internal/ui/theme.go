package ui

import (
	_ "embed"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Charte CACyber (identique à la console web, frontend/src/styles) : encre, papier, bleu, échelle A→E.
var (
	CouleurEncre   = color.NRGBA{R: 0x16, G: 0x22, B: 0x2F, A: 0xFF}
	CouleurPapier  = color.NRGBA{R: 0xF6, G: 0xF7, B: 0xF5, A: 0xFF}
	CouleurBleu    = color.NRGBA{R: 0x1C, G: 0x4E, B: 0x80, A: 0xFF}
	CouleurTexte   = color.NRGBA{R: 0x23, G: 0x2B, B: 0x33, A: 0xFF}
	CouleurDiscret = color.NRGBA{R: 0x5C, G: 0x68, B: 0x73, A: 0xFF}
	CouleurVert    = color.NRGBA{R: 0x0E, G: 0x7C, B: 0x5B, A: 0xFF}
	CouleurAmbre   = color.NRGBA{R: 0x9A, G: 0x5B, B: 0x12, A: 0xFF}
	CouleurRouge   = color.NRGBA{R: 0xA6, G: 0x34, B: 0x2C, A: 0xFF}
	CouleurBordure = color.NRGBA{R: 0xDD, G: 0xE1, B: 0xDC, A: 0xFF}
	CouleurCarte   = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	CouleurEncre2  = color.NRGBA{R: 0x8C, G: 0x9B, B: 0xAA, A: 0xFF} // texte secondaire sur fond encre
)

// CouleursNotes : échelle A→E de la console.
var CouleursNotes = map[string]color.NRGBA{
	"A": {R: 0x0E, G: 0x7C, B: 0x5B, A: 0xFF},
	"B": {R: 0x5C, G: 0x8A, B: 0x3C, A: 0xFF},
	"C": {R: 0xB9, G: 0x8A, B: 0x1C, A: 0xFF},
	"D": {R: 0xB5, G: 0x62, B: 0x2A, A: 0xFF},
	"E": {R: 0xA6, G: 0x34, B: 0x2C, A: 0xFF},
}

// CouleurNote : couleur d'une note (gris si inconnue).
func CouleurNote(n string) color.NRGBA {
	if c, ok := CouleursNotes[n]; ok {
		return c
	}
	return CouleurDiscret
}

// themeCACyber : thème clair aux couleurs de la marque (toujours clair, quelle que soit la
// préférence du système, pour rester fidèle à la charte et aux captures de la documentation).
type themeCACyber struct{}

var _ fyne.Theme = themeCACyber{}

func (themeCACyber) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground:
		return CouleurPapier
	case theme.ColorNameForeground:
		return CouleurTexte
	case theme.ColorNamePrimary, theme.ColorNameFocus, theme.ColorNameHyperlink:
		return CouleurBleu
	case theme.ColorNameForegroundOnPrimary:
		return color.White
	case theme.ColorNameButton:
		return color.NRGBA{R: 0xE9, G: 0xEC, B: 0xE8, A: 0xFF}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 0xEE, G: 0xF0, B: 0xED, A: 0xFF}
	case theme.ColorNameDisabled, theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 0x9A, G: 0xA3, B: 0xAB, A: 0xFF}
	case theme.ColorNameInputBackground, theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return CouleurCarte
	case theme.ColorNameInputBorder, theme.ColorNameSeparator:
		return CouleurBordure
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x1C, G: 0x4E, B: 0x80, A: 0x14}
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0x1C, G: 0x4E, B: 0x80, A: 0x28}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x1C, G: 0x4E, B: 0x80, A: 0x30}
	case theme.ColorNameSuccess:
		return CouleurVert
	case theme.ColorNameWarning:
		return CouleurAmbre
	case theme.ColorNameError:
		return CouleurRouge
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x22}
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0x16, G: 0x22, B: 0x2F, A: 0x55}
	case theme.ColorNameHeaderBackground:
		return CouleurPapier
	}
	return theme.DefaultTheme().Color(n, theme.VariantLight)
}

func (themeCACyber) Font(s fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(s) }

func (themeCACyber) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }

func (themeCACyber) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 17
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 6
	case theme.SizeNamePadding:
		return 5
	}
	return theme.DefaultTheme().Size(n)
}

// ----------------------------------------------------------------------------- ressources embarquées

//go:embed ressources/logomark-blanc.png
var logomarkBlanc []byte

//go:embed ressources/logomark-encre.png
var logomarkEncre []byte

//go:embed ressources/icone.png
var iconeFenetre []byte

var (
	ressourceLogoBlanc = fyne.NewStaticResource("logomark-blanc.png", logomarkBlanc)
	ressourceLogoEncre = fyne.NewStaticResource("logomark-encre.png", logomarkEncre)
	ressourceIcone     = fyne.NewStaticResource("icone.png", iconeFenetre)
)

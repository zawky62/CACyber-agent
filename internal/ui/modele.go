// Package ui : interface graphique NATIVE de l'agent (Fyne, rendu par le système via OpenGL) —
// ni navigateur, ni vue web, ni serveur HTTP local. Un seul exécutable, ressources embarquées.
//
// Ce fichier ne dépend pas de Fyne : il contient le « modèle de vue » (enchaînement des écrans,
// états affichés, messages d'erreur lisibles), testé sans fenêtre.
package ui

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"cacyber/agent/internal/api"
	"cacyber/agent/internal/app"
	"cacyber/agent/internal/journal"
	"cacyber/agent/internal/outils"
	"cacyber/agent/internal/scan"
)

// Agent : actions de l'agent utilisées par l'interface (satisfaite par *app.App ; simulée en test).
type Agent interface {
	Contexte() app.Contexte
	Relier(code string) error
	Verifier() (*api.Moi, error)
	Lancer(ctx context.Context) error
	Transmettre() (*api.Bilan, error)
	Oublier() error
	InstallerOutillageEtAttendre(ctx context.Context, progres func(outils.Etape)) (*outils.Rapport, error)
	EtatOutils() ([]outils.EtatOutil, error)
	InstallerNmap(ctx context.Context) error
	OuvrirNpcap() error
	DefinirProfil(nom string) error
	Profil() string
	DefinirDemo(demo bool) error
	Demo() bool
	Serveur() string
	DossierDonnees() string
	DossierJournaux() string
	Purger(avecJournaux bool) error
}

var _ Agent = (*app.App)(nil)

// Ecran : étapes de l'interface, dans l'ordre du parcours.
type Ecran int

const (
	EcranAccueil Ecran = iota
	EcranAppairage
	EcranOutillage
	EcranScan
	EcranResultat
	EcranParametres
)

// Titres des écrans (barre de navigation).
var TitresEcrans = map[Ecran]string{
	EcranAccueil:    "Accueil",
	EcranAppairage:  "Appairage",
	EcranOutillage:  "Outillage",
	EcranScan:       "Scan",
	EcranResultat:   "Résultat",
	EcranParametres: "Paramètres",
}

// Parcours : ordre d'affichage dans la barre de navigation.
var Parcours = []Ecran{EcranAccueil, EcranAppairage, EcranOutillage, EcranScan, EcranResultat, EcranParametres}

// Accessible indique si un écran peut être ouvert dans l'état courant (étapes reprenables :
// on peut toujours revenir en arrière, jamais sauter une condition).
func Accessible(e Ecran, c app.Contexte) bool {
	switch e {
	case EcranScan:
		return c.Relie
	case EcranResultat:
		return c.Relie && c.Mission != nil && c.Mission.Statut == journal.StatutTransmis
	default:
		return true
	}
}

// EcranConseille : écran sur lequel reprendre, d'après l'état (après un redémarrage notamment).
func EcranConseille(c app.Contexte, accueilVu bool) Ecran {
	switch {
	case !accueilVu:
		return EcranAccueil
	case !c.Relie:
		return EcranAppairage
	case c.Mission != nil && c.Mission.Statut == journal.StatutTransmis:
		return EcranResultat
	case c.Mission != nil && (c.Mission.Statut == journal.StatutScan || c.Mission.Statut == journal.StatutCollecte):
		return EcranScan
	case !c.Demo && c.Outillage.Statut != app.OutillagePret:
		return EcranOutillage // le mode démonstration n'a pas besoin des outils (réseau simulé)
	default:
		return EcranScan
	}
}

// ----------------------------------------------------------------------------- connexion

// Connexion : état de la liaison avec le serveur, affiché en permanence dans l'en-tête.
type Connexion int

const (
	ConnexionInconnue Connexion = iota
	ConnexionEnLigne
	ConnexionHorsLigne
	ConnexionMandatInvalide
)

// TexteConnexion : libellé de l'indicateur d'en-tête.
func TexteConnexion(c Connexion) string {
	switch c {
	case ConnexionEnLigne:
		return "En ligne · mandat valide"
	case ConnexionHorsLigne:
		return "Hors ligne"
	case ConnexionMandatInvalide:
		return "En ligne · mandat non valide"
	default:
		return "Non relié"
	}
}

// ConnexionDepuis interprète le résultat d'une vérification auprès du serveur.
func ConnexionDepuis(moi *api.Moi, err error) Connexion {
	switch {
	case err == nil && moi != nil && moi.MandatValide:
		return ConnexionEnLigne
	case err == nil && moi != nil:
		return ConnexionMandatInvalide
	case EstHorsLigne(err):
		return ConnexionHorsLigne
	default:
		return ConnexionInconnue
	}
}

// EstHorsLigne : l'erreur traduit-elle une absence de réseau (et non un refus du serveur) ?
func EstHorsLigne(err error) bool {
	if err == nil {
		return false
	}
	var ue *url.Error
	var ne net.Error
	var oe *net.OpError
	var de *net.DNSError
	if errors.As(err, &de) || errors.As(err, &oe) || errors.As(err, &ne) || errors.As(err, &ue) {
		return true
	}
	return strings.Contains(err.Error(), "injoignable")
}

// MessageErreur : message lisible en français pour une boîte de dialogue.
func MessageErreur(err error) string {
	if err == nil {
		return ""
	}
	var es *api.ErreurServeur
	switch {
	case EstHorsLigne(err):
		return "Le serveur CACyber est injoignable depuis ce poste.\n\nVérifiez la connexion Internet (ou le proxy de l'entreprise), puis réessayez. " +
			"Rien n'est perdu : l'étape pourra être reprise."
	case errors.As(err, &es) && es.Statut == 401:
		return "Le serveur a refusé l'identité de ce poste (" + es.Message + ").\n\nVérifiez l'heure de l'ordinateur ; si le problème persiste, " +
			"demandez un nouveau code d'appairage à votre cabinet."
	case errors.As(err, &es) && es.Statut == 403:
		return "Refus du serveur : " + es.Message + "\n\nAucun scan n'est possible sans mandat d'autorisation signé et en cours de validité. " +
			"Contactez votre cabinet."
	case errors.As(err, &es):
		return "Le serveur a répondu : " + es.Message
	default:
		m := err.Error()
		return strings.ToUpper(m[:1]) + m[1:]
	}
}

// ----------------------------------------------------------------------------- scan

// ChoixProfil : entrée du sélecteur de profil.
type ChoixProfil struct {
	Nom         string
	Libelle     string
	Description string
}

// ChoixProfils : profils compilés dans l'agent, dans l'ordre d'intensité.
func ChoixProfils() []ChoixProfil {
	desc := map[scan.Profil]string{
		scan.ProfilDecouverte: "Cartographie rapide : quels équipements, quels services courants.",
		scan.ProfilStandard:   "Audit courant : services, versions et contrôles « sûrs ».",
		scan.ProfilApprofondi: "Plus de ports et détection de versions poussée (plus long).",
		scan.ProfilIndustriel: "Réseaux fragiles (automates, OT) : très lent, sans sonde de version, équipements fragiles exclus.",
	}
	var res []ChoixProfil
	for _, nom := range []scan.Profil{scan.ProfilDecouverte, scan.ProfilStandard, scan.ProfilApprofondi, scan.ProfilIndustriel} {
		p, _ := scan.ProfilDepuis(string(nom))
		res = append(res, ChoixProfil{Nom: string(nom), Libelle: p.Libelle, Description: desc[nom]})
	}
	return res
}

// ProfilPreselectionne : choix du poste, sinon proposition du serveur, sinon « standard ».
func ProfilPreselectionne(local, serveur string) string {
	for _, nom := range []string{local, serveur} {
		if _, ok := scan.ProfilDepuis(nom); ok && nom != "" {
			return strings.ToLower(strings.TrimSpace(nom))
		}
	}
	return string(scan.ProfilStandard)
}

// ActionScan : bouton principal de l'écran « Scan » selon l'état de la mission.
type ActionScan int

const (
	ActionLancer ActionScan = iota
	ActionPatienter
	ActionTransmettre
	ActionNouveauScan
)

// ActionDepuis détermine le bouton principal.
func ActionDepuis(m *journal.Instantane) ActionScan {
	if m == nil {
		return ActionLancer
	}
	switch m.Statut {
	case journal.StatutScan:
		return ActionPatienter
	case journal.StatutCollecte:
		return ActionTransmettre
	case journal.StatutTransmis:
		return ActionNouveauScan
	default:
		return ActionLancer
	}
}

// ----------------------------------------------------------------------------- outillage

// SuiviOutils : progression par composant pendant la mise en place.
type SuiviOutils struct {
	Ordre  []string
	Etapes map[string]outils.Etape
}

// NouveauSuivi prépare le suivi (composants connus d'avance affichés immédiatement).
func NouveauSuivi(connus ...string) *SuiviOutils {
	s := &SuiviOutils{Etapes: map[string]outils.Etape{}}
	for _, n := range connus {
		s.Noter(outils.Etape{Outil: n, Texte: "En attente…"})
	}
	return s
}

// Noter enregistre une étape ; une progression indéterminée (-1) conserve la dernière connue.
func (s *SuiviOutils) Noter(e outils.Etape) {
	nom := strings.TrimSpace(e.Outil)
	if nom == "" {
		nom = "général"
	}
	prec, existe := s.Etapes[nom]
	if !existe {
		s.Ordre = append(s.Ordre, nom)
	}
	if e.Progression < 0 {
		e.Progression = prec.Progression
	}
	s.Etapes[nom] = e
}

// NomAffiche : nom lisible d'un composant.
func NomAffiche(nom string) string {
	switch strings.ToLower(nom) {
	case "nmap":
		return "Nmap"
	case "osquery":
		return "osquery"
	case "nuclei":
		return "Nuclei"
	case "nuclei-templates", "modeles", "modèles":
		return "Modèles Nuclei"
	case "sharphound":
		return "SharpHound"
	case "auto-test":
		return "Auto-test (127.0.0.1)"
	default:
		return nom
	}
}

// NoteValide : la note A→E reçue du serveur est-elle affichable ?
func NoteValide(n string) bool { return len(n) == 1 && strings.Contains("ABCDE", n) }

// dateFr : « 2027-02-06 » (ou horodatage ISO) -> « 06/02/2027 » ; valeur inchangée si illisible.
func dateFr(iso string) string {
	if len(iso) < 10 || iso[4] != '-' || iso[7] != '-' {
		return iso
	}
	return iso[8:10] + "/" + iso[5:7] + "/" + iso[0:4]
}

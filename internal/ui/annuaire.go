package ui

// Carte « Active Directory — chemins d'attaque (façon BloodHound) » de l'écran Résultat.
//
// Tout ce qui est affiché ici a été CALCULÉ PAR LE SERVEUR à partir de la collecte en lecture seule
// (l'agent reste un client léger) : compteurs d'hygiène de l'annuaire et chemins de contrôle menant
// aux comptes privilégiés. Il s'agit d'expositions à RÉDUIRE ; aucune indication d'exploitation.

import (
	"fmt"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"cacyber/agent/internal/api"
	"cacyber/agent/internal/journal"
)

// libelleRelation : relation lisible (les noms des droits restent ceux de BloodHound, reconnus des
// équipes informatiques ; l'appartenance est traduite).
func libelleRelation(r string) string {
	if r == "MemberOf" {
		return "MembreDe"
	}
	return r
}

// ChaineChemin : « A --[Relation]--> B --[Relation]--> C » (caractères simples : rendu identique partout).
func ChaineChemin(c api.CheminAD) string {
	if len(c.Etapes) == 0 {
		return c.Depuis
	}
	var b strings.Builder
	b.WriteString(c.Etapes[0].De)
	for _, e := range c.Etapes {
		b.WriteString(" --[" + libelleRelation(e.Relation) + "]--> " + e.Vers)
	}
	return b.String()
}

// Recommandations génériques de durcissement (défensives).
const conseilsAnnuaire = "Ces chemins sont des expositions à RÉDUIRE : retirer les droits excessifs accordés sur les comptes " +
	"et groupes privilégiés (ACL), limiter et surveiller les membres des groupes d'administration, réserver la " +
	"réinitialisation des mots de passe administrateurs à un groupe dédié, supprimer la délégation non contrainte, " +
	"renouveler deux fois le mot de passe du compte krbtgt et désactiver les comptes inactifs."

func nombre(n int) string { return fmt.Sprintf("%d", n) }

// carteAnnuaire construit la carte AD de l'écran Résultat.
func (ui *Interface) carteAnnuaire(m *journal.Instantane) fyne.CanvasObject {
	titreCarte := sousTitre("Active Directory — chemins d'attaque (façon BloodHound)")
	a := m.Annuaire
	if a == nil {
		return carte(titreCarte,
			paragraphe("Poste hors domaine : aucune donnée Active Directory n'a été collectée."),
			discret("Sur un poste membre d'un domaine, l'agent lit l'annuaire en lecture seule et le serveur calcule les "+
				"chemins menant aux comptes privilégiés. Le mode démonstration (--demo) en montre un exemple."))
	}
	objets := []fyne.CanvasObject{titreCarte,
		ligneInfo("Domaine", a.Domaine),
		ligneInfo("Actifs / privilégiés", fmt.Sprintf("%d / %d", a.ComptesActifs, a.ComptesPrivilegies)),
		ligneInfo("Comptes avec un chemin", nombre(a.ComptesAvecChemin)),
	}
	if len(a.GroupesLargesExposes) > 0 {
		objets = append(objets, ligneInfo("Groupes larges exposés", strings.Join(a.GroupesLargesExposes, ", ")))
	}
	objets = append(objets,
		ligneInfo("Comptes avec SPN", nombre(a.Kerberoastables)),
		ligneInfo("Sans pré-auth. Kerberos", nombre(a.ASREP)),
		ligneInfo("Délégation non contrainte", nombre(a.DelegationNonContrainte)),
		ligneInfo("Comptes inactifs", nombre(a.ComptesInactifs)),
	)
	if a.KrbtgtAgeJours != nil {
		objets = append(objets, ligneInfo("Mot de passe krbtgt", fmt.Sprintf("changé il y a %d jours", *a.KrbtgtAgeJours)))
	}
	if a.LAPS != nil {
		objets = append(objets, ligneInfo("LAPS", fmt.Sprintf("%d ordinateur(s) couvert(s) sur %d", a.LAPS.Couverts, a.LAPS.Total)))
	}
	if len(a.Chemins) > 0 {
		objets = append(objets, sousTitre(fmt.Sprintf("Chemins les plus courts vers les comptes privilégiés (%d)", len(a.Chemins))))
		for _, c := range a.Chemins {
			l := widget.NewLabel("• " + ChaineChemin(c))
			l.Wrapping = fyne.TextWrapWord
			objets = append(objets, l)
		}
	} else {
		objets = append(objets, paragraphe("Aucun chemin de contrôle vers les comptes privilégiés n'a été trouvé."))
	}
	objets = append(objets, discret(conseilsAnnuaire))
	if m.ExportBloodHound != "" {
		export := widget.NewButtonWithIcon("Ouvrir l'export BloodHound", theme.FolderOpenIcon(), func() {
			if err := ouvrirDossier(filepath.Dir(m.ExportBloodHound)); err != nil {
				ui.erreur("Export BloodHound", err)
			}
		})
		objets = append(objets, container.NewHBox(export),
			discret("Fichier "+filepath.Base(m.ExportBloodHound)+" : à importer dans BloodHound CE (« Upload Data »)."))
	}
	return carte(objets...)
}

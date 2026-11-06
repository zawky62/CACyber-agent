package ui

import (
	"testing"

	"cacyber/agent/internal/api"
)

// Un chemin s'affiche en chaîne lisible, l'appartenance étant traduite.
func TestChaineChemin(t *testing.T) {
	c := api.CheminAD{Depuis: "Utilisateurs du domaine", Vers: "Admins du domaine", Etapes: []api.EtapeChemin{
		{De: "Utilisateurs du domaine", Relation: "GenericAll", Vers: "admin.it"},
		{De: "admin.it", Relation: "MemberOf", Vers: "Admins du domaine"},
	}}
	if got := ChaineChemin(c); got != "Utilisateurs du domaine --[GenericAll]--> admin.it --[MembreDe]--> Admins du domaine" {
		t.Fatalf("chaîne inattendue : %s", got)
	}
}

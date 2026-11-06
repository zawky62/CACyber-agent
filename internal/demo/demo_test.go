package demo

import (
	"testing"
	"time"
)

// Les dates « @jours:-N » sont résolues par rapport au jour d'exécution.
func TestDatesRelatives(t *testing.T) {
	jour := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	o, err := Observations(jour)
	if err != nil {
		t.Fatal(err)
	}
	if o.Mode != "demo" || len(o.Hotes) != 9 {
		t.Fatalf("jeu inattendu : mode %s, %d hôtes", o.Mode, len(o.Hotes))
	}
	srv := o.Hotes[1]
	if srv.Nom != "SRV-USINE" || srv.Inventaire == nil {
		t.Fatalf("SRV-USINE attendu : %+v", srv)
	}
	if d := *srv.Inventaire.Correctifs[0].InstalleLe; d != "2025-09-22" { // 6 nov. 2026 − 410 jours
		t.Fatalf("date relative mal résolue : %s", d)
	}
	if d := *srv.Inventaire.Sauvegardes.Derniere; d != "2026-11-05" {
		t.Fatalf("sauvegarde : %s", d)
	}
}

// Le jeu de démonstration contient un domaine Active Directory fictif (BREST.LOCAL), dates résolues.
func TestAnnuaireDemo(t *testing.T) {
	o, err := Observations(time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if o.AD == nil || o.AD.Domaine.Nom != "BREST.LOCAL" || len(o.AD.Noeuds) < 15 || len(o.AD.Aretes) < 10 {
		t.Fatalf("annuaire de démonstration attendu : %+v", o.AD)
	}
	for _, n := range o.AD.Noeuds {
		if n.N == "krbtgt" && (n.MdpChange == nil || *n.MdpChange != "2021-08-24") { // 6 nov. 2026 − 1900 jours
			t.Fatalf("date relative du krbtgt mal résolue : %v", n.MdpChange)
		}
	}
}

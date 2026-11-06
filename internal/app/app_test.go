package app

import "testing"

// Le code saisi est normalisé (espaces, casse) puis contrôlé avant tout appel au serveur.
func TestFormatCode(t *testing.T) {
	if !FormatCode.MatchString(NormaliserCode(" cacc-aptv-w8nt-targ-58rj ")) {
		t.Fatal("code valide refusé")
	}
	if FormatCode.MatchString(NormaliserCode("CACC-12-34")) {
		t.Fatal("code invalide accepté")
	}
}

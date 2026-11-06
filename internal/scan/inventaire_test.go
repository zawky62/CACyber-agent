//go:build windows

package scan

import "testing"

// « net accounts » est localisé : les deux langues usuelles doivent être lues.
func TestNetAccountsFrancaisEtAnglais(t *testing.T) {
	fr := "Durée de vie maximale du mot de passe (jours) :           42\r\nLongueur minimale du mot de passe :                    8\r\nSeuil de verrouillage :                                  Jamais\r\n"
	p := AnalyserNetAccounts(fr)
	if *p.LongueurMin != 8 || *p.ExpirationJours != 42 || *p.SeuilVerrouillage != 0 {
		t.Fatalf("FR : %+v", p)
	}
	en := "Minimum password length:                              14\r\nMaximum password age (days):                          Unlimited\r\nLockout threshold:                                    5\r\n"
	p = AnalyserNetAccounts(en)
	if *p.LongueurMin != 14 || *p.ExpirationJours != 0 || *p.SeuilVerrouillage != 5 {
		t.Fatalf("EN : %+v", p)
	}
}

// auditpol /r : la dernière colonne numérique indique le réglage, quelle que soit la langue.
func TestAuditpol(t *testing.T) {
	csv := "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\nPC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n"
	if v, ok := AnalyserAuditpol(csv); !ok || !v {
		t.Fatal("audit des connexions actif attendu")
	}
	csv = "PC,Système,Ouverture de session,{0CCE9215-69AE-11D9-BED3-505054503030},Aucun audit,,0\r\n"
	if v, ok := AnalyserAuditpol(csv); !ok || v {
		t.Fatal("audit des connexions inactif attendu")
	}
}

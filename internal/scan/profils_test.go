package scan

import (
	"strings"
	"testing"
)

// Le serveur ne choisit qu'un NOM de profil ; un nom inconnu retombe sur « standard ».
func TestProfilsEnumeration(t *testing.T) {
	for _, nom := range []string{"decouverte", "standard", "approfondi", "industriel", "Industriel ", ""} {
		if _, ok := ProfilDepuis(nom); !ok {
			t.Errorf("profil %q non reconnu", nom)
		}
	}
	p, ok := ProfilDepuis("-sS -O --script vuln")
	if ok || p.Nom != ProfilStandard {
		t.Fatalf("un nom inconnu doit retomber sur standard sans être interprété : %v %v", p.Nom, ok)
	}
	if len(Profils()) != 4 {
		t.Fatalf("4 profils attendus")
	}
}

// Invariants de sécurité communs à tous les profils.
func TestProfilsInvariants(t *testing.T) {
	for _, p := range Profils() {
		args, err := ArgumentsNmap(p, nil, []string{"smb-protocols", "http-title"}, "T5", "c.txt", false)
		if err != nil {
			t.Fatalf("%s : %v", p.Nom, err)
		}
		ligne := " " + strings.Join(args, " ") + " "
		for _, requis := range []string{" --unprivileged ", " -sT ", " -oX - ", " -iL c.txt "} {
			if !strings.Contains(ligne, requis) {
				t.Errorf("%s : option requise %q absente : %s", p.Nom, requis, ligne)
			}
		}
		for _, interdit := range []string{"-sS", "-sU", " -O ", "-A ", "--script-args", "-T4", "-T5", "vuln", "brute", "exploit", "intrusive", "--data", " -f ", " -D ", "-S "} {
			if strings.Contains(ligne, interdit) {
				t.Errorf("%s : option interdite %q : %s", p.Nom, interdit, ligne)
			}
		}
	}
}

func TestProfilIndustriel(t *testing.T) {
	p, _ := ProfilDepuis("industriel")
	args, _ := ArgumentsNmap(p, []int{80, 102, 443, 502, 9100, 47808}, []string{"smb-protocols"}, "T3", "c.txt", false)
	ligne := strings.Join(args, " ")
	for _, attendu := range []string{"-T2", "--scan-delay 500ms", "--max-rate 5", "--max-parallelism 1", "--max-retries 0", "-p 80,443 "} {
		if !strings.Contains(ligne, attendu) {
			t.Errorf("industriel : %q attendu dans %s", attendu, ligne)
		}
	}
	if strings.Contains(ligne, "-sV") || strings.Contains(ligne, "--script") {
		t.Errorf("industriel : ni sondes de version ni scripts : %s", ligne)
	}
	// Avec l'accord explicite du mandat, les ports fragiles peuvent être examinés.
	if ps := p.Ports([]int{80, 502}, true); len(ps) != 2 {
		t.Errorf("inclure_fragiles ignoré : %v", ps)
	}
	if p.ConcurrenceNative() != 1 {
		t.Errorf("scanner natif trop parallèle en industriel")
	}
}

func TestProfilsPorts(t *testing.T) {
	d, _ := ProfilDepuis("decouverte")
	if ps := d.Ports([]int{22, 502, 3389, 47808}, false); joindre(ps) != "22,3389" {
		t.Errorf("découverte : %v", ps)
	}
	a, _ := ProfilDepuis("approfondi")
	if ps := a.Ports(nil, false); len(ps) <= len(PortsValides(nil)) {
		t.Errorf("approfondi : ports supplémentaires attendus (%d)", len(ps))
	}
	s, _ := ProfilDepuis("standard")
	args, _ := ArgumentsNmap(s, []int{445}, nil, "T2", "c.txt", false)
	if !strings.Contains(strings.Join(args, " "), "-T2") {
		t.Errorf("le serveur doit pouvoir ralentir le profil")
	}
}

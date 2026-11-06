package outils

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func archiveTest(t *testing.T, membres map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for nom, contenu := range membres {
		w, err := z.Create(nom)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(contenu)
	}
	_ = z.Close()
	p := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Seuls les membres de la liste blanche sont extraits, vers des noms fixés : un membre « ../ » de
// l'archive n'est jamais écrit ; empreinte et taille sont contrôlées.
func TestExtractionListeBlanche(t *testing.T) {
	bon := []byte("binaire attendu")
	a := archiveTest(t, map[string][]byte{"outil/bin.exe": bon, "../../evade.exe": []byte("x"), "autre.txt": []byte("y")})
	dest := t.TempDir()
	if err := extraire(a, []Fichier{{Membre: "outil/bin.exe", Dest: "bin.exe", SHA256: sha(bon), Taille: 1 << 10}}, dest); err != nil {
		t.Fatal(err)
	}
	entrees, _ := os.ReadDir(dest)
	if len(entrees) != 1 || entrees[0].Name() != "bin.exe" {
		t.Fatalf("contenu extrait inattendu : %v", entrees)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(dest)), "evade.exe")); err == nil {
		t.Fatal("membre hors liste blanche écrit")
	}
	// Empreinte non conforme
	if err := extraire(a, []Fichier{{Membre: "outil/bin.exe", Dest: "b2.exe", SHA256: sha([]byte("autre")), Taille: 1 << 10}}, t.TempDir()); err == nil {
		t.Fatal("empreinte non conforme acceptée")
	}
	// Taille excessive
	if err := extraire(a, []Fichier{{Membre: "outil/bin.exe", Dest: "b3.exe", SHA256: sha(bon), Taille: 3}}, t.TempDir()); err == nil {
		t.Fatal("membre trop volumineux accepté")
	}
	// Destination non locale
	if err := extraire(a, []Fichier{{Membre: "outil/bin.exe", Dest: "../b4.exe", SHA256: sha(bon), Taille: 1 << 10}}, t.TempDir()); err == nil {
		t.Fatal("destination non locale acceptée")
	}
}

// Téléchargements : HTTPS et sources officielles uniquement (redirections comprises).
func TestSourcesOfficielles(t *testing.T) {
	for _, ok := range []string{"https://github.com/x", "https://release-assets.githubusercontent.com/y", "https://nmap.org/dist/z"} {
		u, _ := url.Parse(ok)
		if verifierURL(u) != nil {
			t.Errorf("source officielle refusée : %s", ok)
		}
	}
	for _, ko := range []string{"http://github.com/x", "https://evil.example/nmap.exe", "https://github.com.evil.example/x", "file:///c:/x"} {
		u, _ := url.Parse(ko)
		if verifierURL(u) == nil {
			t.Errorf("source non officielle acceptée : %s", ko)
		}
	}
	for _, o := range append(append([]Outil{}, Geres...), NmapInstallateur) {
		u, _ := url.Parse(o.URL)
		if verifierURL(u) != nil || len(o.SHA256) != 64 {
			t.Errorf("manifeste de %s invalide", o.Nom)
		}
		for _, f := range o.Fichiers {
			if len(f.SHA256) != 64 || !filepath.IsLocal(f.Dest) {
				t.Errorf("fichier %s de %s : empreinte ou destination invalide", f.Dest, o.Nom)
			}
		}
	}
}


// Un binaire altéré est refusé avant exécution (contrôle d'empreinte).
func TestBinaireAltereRefuse(t *testing.T) {
	dir := t.TempDir()
	o := Outil{Nom: "essai", Version: "1", Executable: "essai.exe",
		Fichiers: []Fichier{{Dest: "essai.exe", SHA256: sha([]byte("original"))}}}
	chemin := filepath.Join(dir, "essai.exe")
	_ = os.WriteFile(chemin, []byte("modifié"), 0o700)
	if _, err := preparerChemin(o, chemin, o.Fichiers[0].SHA256); err == nil || !strings.Contains(err.Error(), "NON CONFORME") {
		t.Fatalf("binaire altéré accepté : %v", err)
	}
	_ = os.WriteFile(chemin, []byte("original"), 0o700)
	x, err := preparerChemin(o, chemin, o.Fichiers[0].SHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Fermer()
	if runtime.GOOS == "windows" {
		// Le binaire vérifié ne peut plus être modifié tant qu'il est préparé.
		if err := os.WriteFile(x.Chemin, []byte("substitution"), 0o700); err == nil {
			t.Fatal("binaire modifiable entre vérification et exécution")
		}
	}
}

// Un composant non signé par son éditeur n'est JAMAIS exécuté, même à l'empreinte conforme.
func TestComposantNonSigneRefuse(t *testing.T) {
	g := &Gestionnaire{Racine: t.TempDir(), Progres: func(Etape) {}}
	o := Outil{Nom: "essai", Version: "1", Executable: "essai.exe",
		Fichiers: []Fichier{{Dest: "essai.exe", SHA256: sha([]byte("original"))}}}
	_ = os.MkdirAll(g.Dossier(o), 0o700)
	_ = os.WriteFile(filepath.Join(g.Dossier(o), "essai.exe"), []byte("original"), 0o700)
	if _, err := g.Preparer(o); err == nil || !strings.Contains(err.Error(), "non signé") {
		t.Fatalf("composant non signé accepté : %v", err)
	}
}

// Tous les outils gérés exigent une signature d'éditeur.
func TestOutilsGeresTousSignes(t *testing.T) {
	for _, o := range Geres {
		if len(o.Signataires) == 0 {
			t.Errorf("%s : aucun signataire exigé", o.Nom)
		}
	}
}

// Aucun dossier d'outillage dans le dossier temporaire du système.
func TestJamaisDansTemp(t *testing.T) {
	if d := DossierParDefaut(); d != "" && strings.HasPrefix(strings.ToLower(d), strings.ToLower(os.TempDir())) {
		t.Fatalf("outillage dans le dossier temporaire : %s", d)
	}
	if _, err := Nouveau("", nil, nil); err == nil {
		t.Fatal("racine vide acceptée")
	}
}

// Identité du signataire Authenticode d'un vrai binaire signé (Nmap installé sur le poste).
func TestSignataireNmap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows uniquement")
	}
	x, err := PreparerNmap("")
	if err != nil {
		t.Skip("Nmap absent de ce poste : ", err)
	}
	defer x.Fermer()
	if !signataireAdmis(x.Signataire, SignatairesNmap) {
		t.Fatalf("signataire inattendu : %q", x.Signataire)
	}
}

func TestSignatureAbsente(t *testing.T) {
	if _, err := OrganisationSignataire(bytes.NewReader([]byte("pas un exécutable"))); err == nil {
		t.Fatal("fichier quelconque accepté comme signé")
	}
	if _, err := SignataireDuPKCS7([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err == nil {
		t.Fatal("PKCS#7 invalide accepté")
	}
}

// Téléchargement réel et vérification de l'installateur officiel de Nmap (sans l'exécuter).
// Lancé seulement si CACYBER_TEST_RESEAU=1 (accès Internet requis).
func TestInstallateurNmapReseau(t *testing.T) {
	if os.Getenv("CACYBER_TEST_RESEAU") != "1" || runtime.GOOS != "windows" {
		t.Skip("test réseau désactivé (CACYBER_TEST_RESEAU=1 pour l'activer)")
	}
	g, err := Nouveau(t.TempDir(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	chemin, err := g.PreparerInstallateurNmap(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	x, err := preparerChemin(NmapInstallateur, chemin, NmapInstallateur.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Fermer()
	if x.Signataire != "Nmap Software LLC" {
		t.Fatalf("signataire inattendu : %q", x.Signataire)
	}
}

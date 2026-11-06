package annuaire

import (
	"archive/zip"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"cacyber/agent/internal/scan"
)

const sidDom = "S-1-5-21-1-2-3"

func vrai() *bool { b := true; return &b }

func annuaireEssai() *scan.Annuaire {
	d := "2026-01-15"
	return &scan.Annuaire{
		Domaine: scan.DomaineAD{Nom: "brest.local", SID: sidDom},
		Noeuds: []scan.NoeudAD{
			{ID: sidDom, T: "d", N: "BREST.LOCAL"},
			{ID: sidDom + "-512", T: "g", N: "Admins du domaine", AdminCount: true},
			{ID: sidDom + "-513", T: "g", N: "Utilisateurs du domaine"},
			{ID: sidDom + "-1110", T: "u", N: "admin.it", Actif: vrai(), AdminCount: true, DerniereConnexion: &d},
			{ID: sidDom + "-1114", T: "u", N: "svc_sql", Actif: vrai(), SPN: true, MdpSansExpiration: true},
			{ID: sidDom + "-1120", T: "c", N: "srv-fichiers.brest.local", Actif: vrai(), DelegNC: true, OS: "Windows Server 2012 R2"},
		},
		Aretes: [][3]string{
			{sidDom + "-1110", "MemberOf", sidDom + "-512"},
			{sidDom + "-513", "GenericAll", sidDom + "-1110"},
			{"S-1-5-11", "WriteDacl", sidDom + "-1120"},
			{sidDom + "-1114", "DCSync", sidDom},
			{sidDom + "-1114", "AllowedToDelegate", sidDom + "-1120"},
		},
	}
}

func lire(t *testing.T, b []byte) fichierBH {
	t.Helper()
	var f fichierBH
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func objetPar(t *testing.T, f fichierBH, sid string) map[string]any {
	t.Helper()
	for _, o := range f.Data {
		if o["ObjectIdentifier"] == sid {
			return o
		}
	}
	t.Fatalf("objet %s absent", sid)
	return nil
}

// Structure « meta »/« data » v6 et correspondance des arêtes avec les ACE BloodHound.
func TestFichiersBloodHound(t *testing.T) {
	fs, err := FichiersBloodHound(annuaireEssai())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"users.json", "groups.json", "computers.json", "domains.json"} {
		f := lire(t, fs[n])
		if f.Meta.Version != 6 || f.Meta.Type != strings.TrimSuffix(n, ".json") || f.Meta.Count != len(f.Data) {
			t.Fatalf("%s : meta incorrecte %+v", n, f.Meta)
		}
	}
	users := lire(t, fs["users.json"])
	admin := objetPar(t, users, sidDom+"-1110")
	p := admin["Properties"].(map[string]any)
	if p["name"] != "ADMIN.IT@BREST.LOCAL" || p["enabled"] != true || p["admincount"] != true {
		t.Fatalf("propriétés utilisateur : %v", p)
	}
	if admin["PrimaryGroupSID"] != sidDom+"-513" {
		t.Fatalf("groupe principal : %v", admin["PrimaryGroupSID"])
	}
	aces := admin["Aces"].([]any)
	if len(aces) != 1 || aces[0].(map[string]any)["RightName"] != "GenericAll" ||
		aces[0].(map[string]any)["PrincipalSID"] != sidDom+"-513" || aces[0].(map[string]any)["PrincipalType"] != "Group" {
		t.Fatalf("ACE GenericAll attendue sur admin.it : %v", aces)
	}
	svc := objetPar(t, users, sidDom+"-1114")
	if sp := svc["Properties"].(map[string]any); sp["hasspn"] != true || sp["pwdneverexpires"] != true {
		t.Fatalf("svc_sql : %v", sp)
	}
	if d := svc["AllowedToDelegate"].([]any); len(d) != 1 || d[0].(map[string]any)["ObjectType"] != "Computer" {
		t.Fatalf("délégation contrainte : %v", d)
	}
	groupes := lire(t, fs["groups.json"])
	da := objetPar(t, groupes, sidDom+"-512")
	if m := da["Members"].([]any); len(m) != 1 || m[0].(map[string]any)["ObjectIdentifier"] != sidDom+"-1110" ||
		m[0].(map[string]any)["ObjectType"] != "User" {
		t.Fatalf("membres des Admins du domaine : %v", m)
	}
	ordis := lire(t, fs["computers.json"])
	srv := objetPar(t, ordis, sidDom+"-1120")
	if srv["Properties"].(map[string]any)["unconstraineddelegation"] != true {
		t.Fatal("délégation non contrainte attendue")
	}
	if a := srv["Aces"].([]any); len(a) != 1 || a[0].(map[string]any)["RightName"] != "WriteDacl" {
		t.Fatalf("ACE WriteDacl attendue : %v", a)
	}
	if s := srv["Sessions"].(map[string]any); s["Collected"] != false {
		t.Fatal("sessions déclarées non collectées attendues")
	}
	doms := lire(t, fs["domains.json"])
	dom := objetPar(t, doms, sidDom)
	droits := map[string]bool{}
	for _, x := range dom["Aces"].([]any) {
		droits[x.(map[string]any)["RightName"].(string)] = true
	}
	if !droits["GetChanges"] || !droits["GetChangesAll"] {
		t.Fatalf("réplication (GetChanges + GetChangesAll) attendue : %v", dom["Aces"])
	}
}

// L'archive contient les quatre fichiers, nommée d'après le domaine et la date.
func TestExporterBloodHound(t *testing.T) {
	dossier := t.TempDir()
	quand := time.Date(2026, 11, 6, 17, 30, 0, 0, time.UTC)
	chemin, err := ExporterBloodHound(annuaireEssai(), dossier, quand)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(chemin, "bloodhound-brest.local-20261106-1730.zip") {
		t.Fatalf("nom inattendu : %s", chemin)
	}
	z, err := zip.OpenReader(chemin)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	vus := map[string]bool{}
	for _, f := range z.File {
		vus[strings.TrimPrefix(f.Name, "20261106173000_")] = true
	}
	for _, n := range []string{"users.json", "groups.json", "computers.json", "domains.json"} {
		if !vus[n] {
			t.Fatalf("%s absent de l'archive : %v", n, vus)
		}
	}
}

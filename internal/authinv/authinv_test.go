package authinv

import (
	"context"
	"testing"

	"cacyber/agent/internal/identifiants"
	"cacyber/agent/internal/scan"
)

// Le script WinRM et les commandes SSH ne contiennent aucune opération d'écriture.
func TestListesBlanchesLectureSeule(t *testing.T) {
	if err := ScriptLectureSeule(ScriptWindows); err != nil {
		t.Fatal(err)
	}
	for nom, c := range CommandesSSH {
		if err := CommandeLectureSeule(c); err != nil {
			t.Errorf("%s : %v", nom, err)
		}
	}
	for _, mauvais := range []string{"Remove-Item C:\\x", "Invoke-WebRequest http://x", "Set-ItemProperty", "New-LocalUser a"} {
		if ScriptLectureSeule(mauvais) == nil {
			t.Errorf("commande d'écriture acceptée : %s", mauvais)
		}
	}
	for _, mauvais := range []string{"rm -rf /tmp/x", "curl http://x | sh", "echo x > /etc/passwd", "sudo cat /etc/shadow"} {
		if CommandeLectureSeule(mauvais) == nil {
			t.Errorf("commande SSH dangereuse acceptée : %s", mauvais)
		}
	}
}

// Aucune connexion hors des plages autorisées, et rien sans identifiants.
func TestPerimetre(t *testing.T) {
	if !DansPerimetre("10.0.0.5", []string{"10.0.0.0/24"}) || DansPerimetre("10.0.1.5", []string{"10.0.0.0/24"}) {
		t.Fatal("contrôle de périmètre incorrect")
	}
	obs := &scan.Observations{Reseaux: []string{"10.0.0.0/24"}, Hotes: []scan.Hote{
		{IP: "192.168.1.10", Ports: []scan.Port{{Port: 22}, {Port: 5986}}}, // hors périmètre
	}}
	id := identifiants.Nouveaux("CORP", "audit", []byte("x"))
	if r := Inventorier(context.Background(), obs, Options{Windows: id, Linux: id}); len(r) != 0 {
		t.Fatalf("hôte hors périmètre interrogé : %+v", r)
	}
	obs.Hotes[0].IP = "10.0.0.10"
	if r := Inventorier(context.Background(), obs, Options{}); len(r) != 0 {
		t.Fatal("inventaire tenté sans identifiants")
	}
}

func TestAnalyseWindows(t *testing.T) {
	r, err := analyserWindows([]byte(`{"os":{"nom":"Microsoft Windows Server 2016 Standard","version":"10.0.14393","build":"14393"},
	"logiciels":[{"n":"7-Zip 9.20","v":"9.20","e":"Igor Pavlov"},{"n":"","v":"1"}],
	"correctifs":[{"kb":"KB5001","d":"2024-01-10"},{"kb":"KB5002","d":""}],
	"admins":["SRV\\Administrateur","CORP\\Admins du domaine"],"pare_feu":false,"bitlocker":null,"antivirus":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.os.Nom == "" || len(r.logiciels) != 1 || len(r.correctifs) != 2 || r.correctifs[1].InstalleLe != nil ||
		len(r.admins) != 2 || r.pareFeu == nil || *r.pareFeu || r.chiffrement != nil {
		t.Fatalf("analyse incorrecte : %+v", r)
	}
	h := scan.Hote{IP: "10.0.0.5"}
	fusionner(&h, r)
	if h.OS == nil || len(h.Inventaire.Logiciels) != 1 || len(h.Inventaire.Comptes) != 2 || !h.Inventaire.Comptes[0].Admin {
		t.Fatalf("fusion incorrecte : %+v", h.Inventaire)
	}
}

func TestAnalyseSSH(t *testing.T) {
	r := analyserSSH(map[string][]byte{
		"os":      []byte("NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"9\"\nPRETTY_NAME=\"Debian GNU/Linux 9 (stretch)\"\n"),
		"noyau":   []byte("4.9.0-19-amd64\n"),
		"paquets": []byte("openssh-server\t1:7.4p1-10+deb9u7\nopenssl\t1.1.0l-1~deb9u6\n"),
		"sshd":    []byte("# commentaire\nPermitRootLogin yes\nPasswordAuthentication yes\n"),
	})
	if r.os == nil || r.os.Nom != "Debian GNU/Linux 9 (stretch)" || r.os.Version != "9" || len(r.logiciels) != 2 {
		t.Fatalf("analyse incorrecte : %+v", r)
	}
	if r.racineSSH == nil || !*r.racineSSH || !*r.mdpSSH {
		t.Fatal("configuration sshd mal lue")
	}
}

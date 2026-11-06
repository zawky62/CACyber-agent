package scan

import (
	"net/netip"
	"strings"
	"testing"
)

// La liste blanche compilée prime sur la politique reçue : tout script hors liste est refusé.
func TestListeBlanche(t *testing.T) {
	ok, refuses := ScriptsAutorises([]string{"smb-protocols", "smb-vuln-ms17-010", "ftp-brute", "http-title", "smb-protocols", "vuln"})
	if strings.Join(ok, ",") != "http-title,smb-protocols" {
		t.Fatalf("autorisés : %v", ok)
	}
	if strings.Join(refuses, ",") != "ftp-brute,smb-vuln-ms17-010,vuln" {
		t.Fatalf("refusés : %v", refuses)
	}
	std, _ := ProfilDepuis("standard")
	if _, err := ArgumentsNmap(std, []int{445}, []string{"smb-vuln-ms17-010"}, "T3", "c.txt", false); err == nil {
		t.Fatal("un script hors liste blanche aurait dû être refusé")
	}
	args, err := ArgumentsNmap(std, []int{445, 0, 70000, 445}, []string{"smb-protocols"}, "T5", "c.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	ligne := strings.Join(args, " ")
	for _, interdit := range []string{"--script-args", "-T5", "-sU", "-O ", "vuln", "brute"} {
		if strings.Contains(ligne, interdit) {
			t.Errorf("option interdite %q dans %q", interdit, ligne)
		}
	}
	if !strings.Contains(ligne, "-p 445 ") || !strings.Contains(ligne, "-T3") {
		t.Errorf("ports / temporisation inattendus : %q", ligne)
	}
}

// Seules des plages privées de /16 à /32 sont admises ; la limite d'hôtes s'applique.
func TestCiblesPlagesPrivees(t *testing.T) {
	c, err := CalculerCibles([]string{"10.10.2.0/24"}, nil, 1024)
	if err != nil || len(c.Hotes) != 254 || c.Hotes[0].String() != "10.10.2.1" {
		t.Fatalf("/24 : %d hôtes, %v", len(c.Hotes), err)
	}
	if _, err := CalculerCibles([]string{"8.8.8.0/24"}, nil, 1024); err == nil {
		t.Fatal("une plage publique aurait dû être refusée")
	}
	if _, err := CalculerCibles([]string{"10.0.0.0/8"}, nil, 1024); err == nil {
		t.Fatal("une plage plus large que /16 aurait dû être refusée")
	}
	c, _ = CalculerCibles([]string{"127.0.0.1/32"}, nil, 1024)
	if len(c.Hotes) != 1 || c.Hotes[0].String() != "127.0.0.1" {
		t.Fatalf("/32 : %v", c.Hotes)
	}
	c, _ = CalculerCibles([]string{"192.168.0.0/16"}, nil, 100)
	if len(c.Hotes) != 100 || !c.Tronque {
		t.Fatalf("limite d'hôtes non appliquée : %d", len(c.Hotes))
	}
	// Sans plage : /24 autour de l'adresse privée du poste ; les interfaces publiques sont ignorées.
	itf := []netip.Prefix{netip.MustParsePrefix("192.168.1.37/16"), netip.MustParsePrefix("81.2.3.4/24")}
	c, _ = CalculerCibles(nil, itf, 1024)
	if len(c.Reseaux) != 1 || c.Reseaux[0] != "192.168.1.0/24" {
		t.Fatalf("réseaux locaux : %v", c.Reseaux)
	}
}

const xmlNmap = `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
 <host><status state="up"/><address addr="10.10.2.5" addrtype="ipv4"/>
  <hostnames><hostname name="srv-usine.artois.local" type="PTR"/></hostnames>
  <ports>
   <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.3"/>
    <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>
   <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" ostype="Windows"/></port>
   <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/>
    <script id="rdp-enum-encryption" output="&#xa;  Security layer&#xa;    CredSSP (NLA): SUCCESS&#xa;    Native RDP: SUCCESS&#xa;"/></port>
   <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
  </ports>
  <hostscript>
   <script id="smb-protocols" output="&#xa;  dialects: &#xa;    NT LM 0.12 (SMBv1) [dangerous, but default]&#xa;    2:0:2&#xa;    3:1:1"/>
   <script id="smb2-security-mode" output="&#xa;  3:1:1: &#xa;    Message signing enabled but not required"/>
   <script id="smb-os-discovery" output="..."><elem key="os">Windows Server 2012 R2 Standard 9600</elem></script>
  </hostscript>
 </host>
 <host><status state="down"/><address addr="10.10.2.6" addrtype="ipv4"/></host>
</nmaprun>`

// Conversion de la sortie XML de Nmap en observations.
func TestAnalyseXMLNmap(t *testing.T) {
	hotes, meta, err := AnalyserXMLNmap([]byte(xmlNmap))
	if err != nil || len(hotes) != 1 || meta["version"] != "7.95" {
		t.Fatalf("analyse : %v %v %v", hotes, meta, err)
	}
	h := hotes[0]
	if h.Nom != "SRV-USINE" || len(h.Ports) != 3 {
		t.Fatalf("hôte : %+v", h)
	}
	if h.FtpAnonyme == nil || !*h.FtpAnonyme {
		t.Error("FTP anonyme non relevé")
	}
	if h.RdpNla == nil || *h.RdpNla {
		t.Error("RDP natif accepté : NLA doit être « non exigée »")
	}
	if h.Smb == nil || strings.Join(h.Smb.Dialectes, "|") != "NT LM 0.12 (SMBv1)|2.0.2|3.1.1" {
		t.Errorf("dialectes : %+v", h.Smb)
	}
	if h.Smb.SignatureRequise == nil || *h.Smb.SignatureRequise {
		t.Error("signature SMB : « non exigée » attendu")
	}
	if h.OS == nil || h.OS.Nom != "Windows Server 2012 R2 Standard 9600" {
		t.Errorf("OS : %+v", h.OS)
	}
}

// Les limites du schéma serveur sont appliquées avant l'envoi.
func TestBornerSchema(t *testing.T) {
	o := Observations{Hotes: []Hote{{IP: "10.0.0.1", Nom: strings.Repeat("x", 500)}}}
	o.Borner()
	if len([]rune(o.Hotes[0].Nom)) != MaxCourt {
		t.Fatal("chaîne non bornée")
	}
}

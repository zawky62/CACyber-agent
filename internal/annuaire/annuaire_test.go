package annuaire

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ------------------------------------------------------------------ fabrication de données binaires

const dom = "S-1-5-21-1111-2222-3333"

// sidBinaire : forme binaire d'un SID textuel.
func sidBinaire(t *testing.T, s string) []byte {
	p := strings.Split(s, "-")
	auto, _ := strconv.ParseUint(p[2], 10, 48)
	b := []byte{1, byte(len(p) - 3), 0, 0, 0, 0, 0, 0}
	for i := 0; i < 6; i++ {
		b[2+i] = byte(auto >> (8 * (5 - i)))
	}
	for _, x := range p[3:] {
		n, err := strconv.ParseUint(x, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
	}
	return b
}

func guidBinaire(g string) []byte {
	h := strings.ReplaceAll(g, "-", "")
	var raw [16]byte
	for i := 0; i < 16; i++ {
		v, _ := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		raw[i] = byte(v)
	}
	b := make([]byte, 16)
	// trois premiers champs en petit-boutiste
	b[0], b[1], b[2], b[3] = raw[3], raw[2], raw[1], raw[0]
	b[4], b[5] = raw[5], raw[4]
	b[6], b[7] = raw[7], raw[6]
	copy(b[8:], raw[8:])
	return b
}

type aceT struct {
	sid      string
	masque   uint32
	objet    string // GUID (ACE objet) ou ""
	drapeaux byte
	refus    bool
}

// descripteur : descripteur auto-relatif avec propriétaire et DACL.
func descripteur(t *testing.T, proprietaire string, aces ...aceT) []byte {
	var acl []byte
	for _, a := range aces {
		var corps []byte
		typ := byte(0x00)
		if a.refus {
			typ = 0x01
		}
		corps = binary.LittleEndian.AppendUint32(corps, a.masque)
		if a.objet != "" {
			typ = 0x05
			if a.refus {
				typ = 0x06
			}
			corps = binary.LittleEndian.AppendUint32(corps, 1)
			corps = append(corps, guidBinaire(a.objet)...)
		}
		corps = append(corps, sidBinaire(t, a.sid)...)
		ace := []byte{typ, a.drapeaux, 0, 0}
		binary.LittleEndian.PutUint16(ace[2:], uint16(4+len(corps)))
		acl = append(acl, append(ace, corps...)...)
	}
	entete := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(entete[2:], uint16(8+len(acl)))
	binary.LittleEndian.PutUint16(entete[4:], uint16(len(aces)))
	dacl := append(entete, acl...)
	prop := sidBinaire(t, proprietaire)
	sd := make([]byte, 20)
	sd[0] = 1
	binary.LittleEndian.PutUint32(sd[4:], 20)
	binary.LittleEndian.PutUint32(sd[16:], uint32(20+len(prop)))
	return append(append(sd, prop...), dacl...)
}

func entree(dn string, attrs map[string]string, bin map[string][]byte) Entree {
	e := Entree{DN: dn, Attrs: map[string][][]byte{}}
	for k, v := range attrs {
		for _, x := range strings.Split(v, "|") {
			e.Attrs[k] = append(e.Attrs[k], []byte(x))
		}
	}
	for k, v := range bin {
		e.Attrs[k] = [][]byte{v}
	}
	return e
}

// ------------------------------------------------------------------ tests

func TestSIDEtGUID(t *testing.T) {
	s := dom + "-1104"
	if got, err := SIDTexte(sidBinaire(t, s)); err != nil || got != s {
		t.Fatalf("SID : %q %v", got, err)
	}
	if GUIDTexte(guidBinaire(guidForceChangePwd)) != guidForceChangePwd {
		t.Fatal("GUID mal décodé")
	}
	if _, err := SIDTexte([]byte{1, 5, 0}); err == nil {
		t.Fatal("SID tronqué accepté")
	}
}

func TestDescripteur(t *testing.T) {
	alice, bob, carole, helpdesk := dom+"-1104", dom+"-1105", dom+"-1106", dom+"-1200"
	sd := descripteur(t, alice,
		aceT{sid: bob, masque: droitGenericAll},
		aceT{sid: carole, masque: droitWriteDac | droitWriteOwner},
		aceT{sid: helpdesk, masque: droitExtended, objet: guidForceChangePwd},
		aceT{sid: dom + "-1300", masque: droitWriteProp, objet: guidMember},
		aceT{sid: dom + "-1400", masque: droitGenericAll, drapeaux: 0x08}, // héritage seulement : ignorée
		aceT{sid: dom + "-1500", masque: droitGenericAll, refus: true},    // refus : ignorée
	)
	d, err := AnalyserDescripteur(sd, true)
	if err != nil {
		t.Fatal(err)
	}
	if d.Proprietaire != alice {
		t.Fatalf("propriétaire : %s", d.Proprietaire)
	}
	attendus := map[string]string{bob: "GenericAll", carole + "/WriteDacl": "", carole + "/WriteOwner": "",
		helpdesk: "ForceChangePassword", dom + "-1300": "AddMember"}
	vus := map[string]bool{}
	for _, dr := range d.Droits {
		vus[dr.SID+"/"+dr.Type] = true
		if strings.HasSuffix(dr.SID, "-1400") || strings.HasSuffix(dr.SID, "-1500") {
			t.Fatalf("ACE ignorable prise en compte : %+v", dr)
		}
	}
	for k, v := range attendus {
		cle := k
		if v != "" {
			cle = k + "/" + v
		}
		if !vus[cle] {
			t.Errorf("droit attendu absent : %s (%v)", cle, vus)
		}
	}
}

// Domaine synthétique : un chemin connu de « stagiaire » vers les administrateurs du domaine.
func TestConstruireGraphe(t *testing.T) {
	stagiaire, helpdesk, admin := dom+"-1104", dom+"-1200", dom+"-500"
	da, du := dom+"-512", dom+"-513"
	serveur, dc := dom+"-2001", dom+"-1000"
	base := "DC=corp,DC=local"
	c := Collecte{
		NomDomaine: "corp.local",
		Domaine: entree(base, map[string]string{"minpwdlength": "7", "maxpwdage": "0", "lockoutthreshold": "0",
			"pwdproperties": "0", "pwdhistorylength": "24", "ms-ds-machineaccountquota": "10"},
			map[string][]byte{"objectsid": sidBinaire(t, dom), "ntsecuritydescriptor": descripteur(t, da,
				aceT{sid: helpdesk, masque: droitExtended, objet: guidGetChanges},
				aceT{sid: helpdesk, masque: droitExtended, objet: guidGetChangesAll})}),
		Utilisateurs: []Entree{
			entree("CN=Stagiaire,"+base, map[string]string{"samaccountname": "stagiaire", "useraccountcontrol": "66048",
				"primarygroupid": "513", "lastlogontimestamp": "133000000000000000"},
				map[string][]byte{"objectsid": sidBinaire(t, stagiaire)}),
			entree("CN=Administrateur,"+base, map[string]string{"samaccountname": "Administrateur", "useraccountcontrol": "512",
				"admincount": "1", "primarygroupid": "513", "serviceprincipalname": "MSSQLSvc/srv:1433"},
				map[string][]byte{"objectsid": sidBinaire(t, admin), "ntsecuritydescriptor": descripteur(t, da,
					aceT{sid: dom + "-1300", masque: droitExtended, objet: guidForceChangePwd})}),
			entree("CN=krbtgt,"+base, map[string]string{"samaccountname": "krbtgt", "useraccountcontrol": "514",
				"serviceprincipalname": "kadmin/changepw", "pwdlastset": "130000000000000000"},
				map[string][]byte{"objectsid": sidBinaire(t, dom+"-502")}),
		},
		Groupes: []Entree{
			entree("CN=Admins du domaine,"+base, map[string]string{"samaccountname": "Admins du domaine", "admincount": "1",
				"member": "CN=Administrateur," + base}, map[string][]byte{"objectsid": sidBinaire(t, da)}),
			entree("CN=Helpdesk,"+base, map[string]string{"samaccountname": "Helpdesk",
				"member": "CN=Stagiaire," + base + "|CN=S-1-5-11,CN=ForeignSecurityPrincipals," + base},
				map[string][]byte{"objectsid": sidBinaire(t, helpdesk)}),
			entree("CN=Utilisateurs du domaine,"+base, map[string]string{"samaccountname": "Utilisateurs du domaine"},
				map[string][]byte{"objectsid": sidBinaire(t, du), "ntsecuritydescriptor": descripteur(t, da)}),
		},
		Ordinateurs: []Entree{
			entree("CN=SRV-APP,"+base, map[string]string{"samaccountname": "SRV-APP$", "dnshostname": "srv-app.corp.local",
				"useraccountcontrol": "528384", "operatingsystem": "Windows Server 2012 R2",
				"msds-allowedtodelegateto": "cifs/dc01.corp.local", "ms-mcs-admpwdexpirationtime": "133"},
				map[string][]byte{"objectsid": sidBinaire(t, serveur)}),
			entree("CN=DC01,"+base, map[string]string{"samaccountname": "DC01$", "dnshostname": "dc01.corp.local",
				"useraccountcontrol": "532480", "primarygroupid": "516"},
				map[string][]byte{"objectsid": sidBinaire(t, dc), "msds-allowedtoactonbehalfofotheridentity": descripteur(t, da,
					aceT{sid: stagiaire, masque: droitControleTot})}),
		},
		SchemaLAPSLegacy: true,
	}
	a := Construire(c)
	if a.Domaine.SID != dom || a.Collecte != "ldap" || a.Tronque {
		t.Fatalf("domaine : %+v", a.Domaine)
	}
	if p := a.PolitiqueMdp; *p.LongueurMin != 7 || *p.AgeMaxJours != 0 || *p.Complexite || *p.SeuilVerrouillage != 0 {
		t.Fatalf("politique : %+v", p)
	}
	if *a.QuotaMachines != 10 || a.LAPS.OrdinateursCouverts != 1 || a.LAPS.OrdinateursTotal != 2 || !a.LAPS.SchemaLegacy {
		t.Fatalf("quota / LAPS : %+v %+v", a.QuotaMachines, a.LAPS)
	}
	noeuds := map[string]int{}
	for i, n := range a.Noeuds {
		noeuds[n.ID] = i
	}
	st := a.Noeuds[noeuds[stagiaire]]
	if !st.MdpSansExpiration || *st.Actif != true || st.DerniereConnexion == nil {
		t.Fatalf("indicateurs du stagiaire : %+v", st)
	}
	if !a.Noeuds[noeuds[admin]].SPN || a.Noeuds[noeuds[dom+"-502"]].SPN {
		t.Fatal("SPN : compte administrateur signalé, krbtgt jamais")
	}
	if !a.Noeuds[noeuds[serveur]].DelegNC || !a.Noeuds[noeuds[dc]].DC || a.Noeuds[noeuds[dc]].DelegNC {
		t.Fatal("délégation non contrainte / contrôleur mal qualifiés")
	}
	aretes := map[string]bool{}
	for _, x := range a.Aretes {
		aretes[x[0]+" "+x[1]+" "+x[2]] = true
	}
	for _, attendu := range []string{
		stagiaire + " MemberOf " + helpdesk,         // appartenance explicite
		stagiaire + " MemberOf " + du,               // groupe principal
		"S-1-5-11 MemberOf " + helpdesk,             // principal bien connu (Utilisateurs authentifiés)
		admin + " MemberOf " + da,                   //
		helpdesk + " DCSync " + dom,                 // les DEUX droits de réplication
		dom + "-1300 ForceChangePassword " + admin,  // droit étendu ciblé
		serveur + " AllowedToDelegate " + dc,        // délégation contrainte vers le contrôleur
		stagiaire + " AllowedToAct " + dc,           // délégation basée sur la ressource
	} {
		if !aretes[attendu] {
			t.Errorf("arête attendue absente : %s", attendu)
		}
	}
	for k := range aretes {
		if strings.HasPrefix(k, da+" ") && !strings.Contains(k, " MemberOf ") {
			t.Errorf("droits des administrateurs du domaine transmis inutilement : %s", k)
		}
	}
}

// Aucun attribut secret ne peut être demandé, même par erreur.
func TestAttributsSecretsRefuses(t *testing.T) {
	for _, l := range [][]string{AttributsUtilisateur, AttributsGroupe, AttributsOrdinateur, AttributsDomaine} {
		if err := verifierAttributs(l); err != nil {
			t.Fatalf("liste d'attributs non conforme : %v", err)
		}
	}
	for _, a := range []string{"ms-Mcs-AdmPwd", "msLAPS-Password", "unicodePwd", "msLAPS-EncryptedPassword"} {
		if verifierAttributs([]string{a}) == nil {
			t.Errorf("attribut secret accepté : %s", a)
		}
	}
}

// Encodage du contrôle SD_FLAGS : SEQUENCE { type, criticité, OCTET STRING(SEQUENCE { INTEGER }) }.
func TestControleSDFlags(t *testing.T) {
	p := controleSDFlags{flags: 5}.Encode()
	if len(p.Children) != 3 || p.Children[0].Value.(string) != "1.2.840.113556.1.4.801" {
		t.Fatalf("contrôle mal formé : %v", p.Children)
	}
	v := ber.DecodePacket(p.Children[2].Data.Bytes())
	if v == nil || len(v.Children) != 1 || v.Children[0].Value.(int64) != 5 {
		t.Fatalf("valeur SD_FLAGS incorrecte : %+v", v)
	}
}

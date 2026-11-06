package annuaire

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"
	"time"

	"cacyber/agent/internal/scan"
)

// Entree : objet LDAP réduit (nom distinctif + attributs, noms en minuscules, valeurs brutes).
type Entree struct {
	DN    string
	Attrs map[string][][]byte
}

func (e Entree) texte(a string) string {
	if v := e.Attrs[a]; len(v) > 0 {
		return string(v[0])
	}
	return ""
}

func (e Entree) brut(a string) []byte {
	if v := e.Attrs[a]; len(v) > 0 {
		return v[0]
	}
	return nil
}

func (e Entree) entier(a string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(e.texte(a)), 10, 64)
	return n, err == nil
}

func (e Entree) sid() string {
	s, _ := SIDTexte(e.brut("objectsid"))
	return s
}

// Indicateurs de userAccountControl.
const (
	uacDesactive       = 0x2
	uacDC              = 0x2000 // SERVER_TRUST_ACCOUNT
	uacSansExpiration  = 0x10000
	uacDelegationNC    = 0x80000
	uacSansPreAuth     = 0x400000
)

// Collecte : objets lus dans l'annuaire, avant mise en forme.
type Collecte struct {
	NomDomaine        string
	NiveauFonctionnel *int
	Controleurs       []string
	Domaine           Entree
	Utilisateurs      []Entree
	Groupes           []Entree
	Ordinateurs       []Entree
	SchemaLAPSLegacy  bool
	SchemaLAPSWindows bool
}

// suffixesExclus : principaux privilégiés par nature dont les droits n'ouvrent aucun chemin nouveau
// (ils sont déjà au sommet) — retirés pour alléger le graphe transmis.
var suffixesExclus = []string{"-512", "-516", "-518", "-519"}
var sidsExclus = map[string]bool{
	"S-1-5-18": true, "S-1-3-0": true, "S-1-5-10": true, "S-1-5-32-544": true, "S-1-5-9": true,
}

func exclu(sid, domaine string) bool {
	if sidsExclus[sid] {
		return true
	}
	for _, s := range suffixesExclus {
		if sid == domaine+s {
			return true
		}
	}
	return false
}

// dateFiletime : horodatage Windows (centaines de ns depuis 1601) -> AAAA-MM-JJ ; nil si jamais.
func dateFiletime(v string) *string {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 || n == 0x7FFFFFFFFFFFFFFF {
		return nil
	}
	t := time.Unix(n/10_000_000-11644473600, 0).UTC().Format("2006-01-02")
	return &t
}

func pInt(n int64) *int { v := int(n); return &v }

// Construire met en forme la collecte : nœuds, arêtes de contrôle dédoublonnées, politique, LAPS.
func Construire(c Collecte) scan.Annuaire {
	domSID := c.Domaine.sid()
	a := scan.Annuaire{Domaine: scan.DomaineAD{Nom: c.NomDomaine, SID: domSID, NiveauFonctionnel: c.NiveauFonctionnel,
		Controleurs: c.Controleurs}, Collecte: "ldap"}

	// Politique du domaine.
	d := c.Domaine
	pol := &scan.PolitiqueMdpAD{}
	if v, ok := d.entier("minpwdlength"); ok {
		pol.LongueurMin = pInt(v)
	}
	if v, ok := d.entier("pwdhistorylength"); ok {
		pol.Historique = pInt(v)
	}
	if v, ok := d.entier("maxpwdage"); ok {
		jours := int64(0) // 0 : pas d'expiration
		if v < 0 && v != -0x8000000000000000 {
			jours = -v / 10_000_000 / 86400
		}
		pol.AgeMaxJours = pInt(jours)
	}
	if v, ok := d.entier("lockoutthreshold"); ok {
		pol.SeuilVerrouillage = pInt(v)
	}
	if v, ok := d.entier("pwdproperties"); ok {
		b := v&1 == 1
		pol.Complexite = &b
	}
	a.PolitiqueMdp = pol
	if v, ok := d.entier("ms-ds-machineaccountquota"); ok {
		a.QuotaMachines = pInt(v)
	}

	// Correspondances nom distinctif -> SID et nom d'hôte -> SID (délégations).
	parDN := map[string]string{strings.ToLower(d.DN): domSID}
	parHote := map[string]string{}
	for _, l := range [][]Entree{c.Utilisateurs, c.Groupes, c.Ordinateurs} {
		for _, e := range l {
			parDN[strings.ToLower(e.DN)] = e.sid()
		}
	}
	for _, e := range c.Ordinateurs {
		s := e.sid()
		if h := strings.ToLower(e.texte("dnshostname")); h != "" {
			parHote[h] = s
			parHote[strings.SplitN(h, ".", 2)[0]] = s
		}
		if n := strings.ToLower(strings.TrimSuffix(e.texte("samaccountname"), "$")); n != "" {
			parHote[n] = s
		}
	}

	aretes := map[[3]string]bool{}
	ajout := func(src, typ, dst string) {
		if src == "" || dst == "" || src == dst {
			return
		}
		aretes[[3]string{src, typ, dst}] = true
	}
	acl := func(e Entree, sid string, groupe bool) {
		sd := e.brut("ntsecuritydescriptor")
		if sd == nil {
			return
		}
		ds, err := AnalyserDescripteur(sd, groupe)
		if err != nil {
			return
		}
		if ds.Proprietaire != "" && !exclu(ds.Proprietaire, domSID) {
			ajout(ds.Proprietaire, "Owns", sid)
		}
		changes, changesAll := map[string]bool{}, map[string]bool{}
		for _, dr := range ds.Droits {
			if exclu(dr.SID, domSID) {
				continue
			}
			switch dr.Type {
			case "GetChanges":
				changes[dr.SID] = true
			case "GetChangesAll":
				changesAll[dr.SID] = true
			default:
				ajout(dr.SID, dr.Type, sid)
			}
		}
		for s := range changes { // réplication de l'annuaire (« DCSync ») : les deux droits sont nécessaires
			if changesAll[s] {
				ajout(s, "DCSync", sid)
			}
		}
	}
	delegations := func(e Entree, sid string) {
		for _, spn := range e.Attrs["msds-allowedtodelegateto"] {
			hote := strings.ToLower(string(spn))
			if i := strings.Index(hote, "/"); i >= 0 {
				hote = hote[i+1:]
			}
			hote = strings.SplitN(hote, ":", 2)[0]
			hote = strings.SplitN(hote, "/", 2)[0]
			if cible := parHote[hote]; cible != "" {
				ajout(sid, "AllowedToDelegate", cible)
			}
		}
	}
	appartenance := func(e Entree, sid string) {
		if pg, ok := e.entier("primarygroupid"); ok && domSID != "" {
			ajout(sid, "MemberOf", domSID+"-"+strconv.FormatInt(pg, 10))
		}
	}

	// Domaine.
	a.Noeuds = append(a.Noeuds, scan.NoeudAD{ID: domSID, T: "d", N: c.NomDomaine})
	acl(d, domSID, false)

	// Utilisateurs.
	for _, e := range c.Utilisateurs {
		sid := e.sid()
		if sid == "" {
			continue
		}
		uac, _ := e.entier("useraccountcontrol")
		actif := uac&uacDesactive == 0
		nom := e.texte("samaccountname")
		n := scan.NoeudAD{ID: sid, T: "u", N: nom, Actif: &actif, AdminCount: e.texte("admincount") == "1",
			SPN: len(e.Attrs["serviceprincipalname"]) > 0 && !strings.EqualFold(nom, "krbtgt"),
			ASREP: uac&uacSansPreAuth != 0, MdpSansExpiration: uac&uacSansExpiration != 0, DelegNC: uac&uacDelegationNC != 0,
			DerniereConnexion: dateFiletime(e.texte("lastlogontimestamp")), MdpChange: dateFiletime(e.texte("pwdlastset"))}
		a.Noeuds = append(a.Noeuds, n)
		appartenance(e, sid)
		acl(e, sid, false)
		delegations(e, sid)
	}
	// Groupes.
	for _, e := range c.Groupes {
		sid := e.sid()
		if sid == "" {
			continue
		}
		a.Noeuds = append(a.Noeuds, scan.NoeudAD{ID: sid, T: "g", N: e.texte("samaccountname"), AdminCount: e.texte("admincount") == "1"})
		for _, m := range e.Attrs["member"] {
			dn := strings.ToLower(string(m))
			membre := parDN[dn]
			if membre == "" && strings.HasPrefix(dn, "cn=s-1-") { // principal de sécurité étranger / bien connu
				membre = strings.ToUpper(strings.SplitN(strings.TrimPrefix(dn, "cn="), ",", 2)[0])
				membre = "S" + membre[1:]
			}
			ajout(membre, "MemberOf", sid)
		}
		acl(e, sid, true)
	}
	// Ordinateurs.
	couverts := 0
	for _, e := range c.Ordinateurs {
		sid := e.sid()
		if sid == "" {
			continue
		}
		uac, _ := e.entier("useraccountcontrol")
		actif := uac&uacDesactive == 0
		nom := e.texte("dnshostname")
		if nom == "" {
			nom = strings.TrimSuffix(e.texte("samaccountname"), "$")
		}
		dc := uac&uacDC != 0
		a.Noeuds = append(a.Noeuds, scan.NoeudAD{ID: sid, T: "c", N: nom, Actif: &actif, DC: dc,
			DelegNC: uac&uacDelegationNC != 0 && !dc, OS: e.texte("operatingsystem"),
			DerniereConnexion: dateFiletime(e.texte("lastlogontimestamp"))})
		if len(e.Attrs["ms-mcs-admpwdexpirationtime"]) > 0 || len(e.Attrs["mslaps-passwordexpirationtime"]) > 0 {
			couverts++
		}
		appartenance(e, sid)
		acl(e, sid, false)
		delegations(e, sid)
		for _, s := range sidsAutorises(e.brut("msds-allowedtoactonbehalfofotheridentity")) {
			ajout(s, "AllowedToAct", sid)
		}
	}
	a.LAPS = &scan.LapsAD{SchemaLegacy: c.SchemaLAPSLegacy, SchemaWindows: c.SchemaLAPSWindows,
		OrdinateursCouverts: couverts, OrdinateursTotal: len(c.Ordinateurs)}

	// Arêtes triées (sortie déterministe) puis bornes.
	for k := range aretes {
		a.Aretes = append(a.Aretes, k)
	}
	trierAretes(a.Aretes)
	if len(a.Noeuds) > scan.MaxNoeudsAD {
		a.Noeuds, a.Tronque = a.Noeuds[:scan.MaxNoeudsAD], true
	}
	if len(a.Aretes) > scan.MaxAretesAD {
		a.Aretes, a.Tronque = a.Aretes[:scan.MaxAretesAD], true
	}
	if a.Aretes == nil {
		a.Aretes = [][3]string{}
	}
	return a
}

// trierAretes : ordre déterministe (source, type, cible).
func trierAretes(l [][3]string) {
	sort.Slice(l, func(i, j int) bool {
		if l[i][0] != l[j][0] {
			return l[i][0] < l[j][0]
		}
		if l[i][1] != l[j][1] {
			return l[i][1] < l[j][1]
		}
		return l[i][2] < l[j][2]
	})
}

// sidsAutorises : SID des ACE d'autorisation d'un descripteur (délégation basée sur la ressource).
func sidsAutorises(sd []byte) []string {
	if len(sd) < 20 {
		return nil
	}
	offDacl := binary.LittleEndian.Uint32(sd[16:20])
	if offDacl == 0 || int(offDacl)+8 > len(sd) {
		return nil
	}
	acl := sd[offDacl:]
	n := int(binary.LittleEndian.Uint16(acl[4:6]))
	var res []string
	pos := 8
	for i := 0; i < n && pos+8 <= len(acl); i++ {
		taille := int(binary.LittleEndian.Uint16(acl[pos+2 : pos+4]))
		if taille < 8 || pos+taille > len(acl) {
			break
		}
		if acl[pos] == 0x00 {
			if s, err := SIDTexte(acl[pos+8 : pos+taille]); err == nil {
				res = append(res, s)
			}
		}
		pos += taille
	}
	return res
}

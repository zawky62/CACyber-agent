package annuaire

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"cacyber/agent/internal/identifiants"
	"cacyber/agent/internal/scan"
)

// Attributs LUS (liste fermée). Les attributs secrets ne figurent JAMAIS ici ; AttributsInterdits est
// vérifié par les tests et à l'exécution.
var (
	AttributsCommuns = []string{"distinguishedName", "objectSid", "sAMAccountName", "nTSecurityDescriptor"}
	AttributsUtilisateur = append(append([]string{}, AttributsCommuns...), "userAccountControl", "lastLogonTimestamp",
		"pwdLastSet", "adminCount", "servicePrincipalName", "primaryGroupID", "msDS-AllowedToDelegateTo")
	AttributsGroupe      = append(append([]string{}, AttributsCommuns...), "member", "adminCount")
	AttributsOrdinateur  = append(append([]string{}, AttributsCommuns...), "dNSHostName", "userAccountControl",
		"operatingSystem", "lastLogonTimestamp", "primaryGroupID", "msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime")
	AttributsDomaine = []string{"distinguishedName", "objectSid", "minPwdLength", "pwdHistoryLength", "maxPwdAge",
		"lockoutThreshold", "pwdProperties", "ms-DS-MachineAccountQuota", "nTSecurityDescriptor"}
	// AttributsInterdits : secrets jamais demandés (mots de passe LAPS, empreintes de mots de passe).
	AttributsInterdits = []string{"ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword",
		"mslaps-encrypteddsrmpassword", "unicodepwd", "userpassword", "supplementalcredentials", "dbcspwd",
		"ntpwdhistory", "lmpwdhistory", "msds-managedpassword"}
)

// Options : paramètres de la collecte.
type Options struct {
	Domaine string // nom DNS ; par défaut celui du poste (USERDNSDOMAIN)
	// Identifiants fournis par l'entité (facultatif) ; sinon identité Windows courante (Kerberos).
	Identifiants *identifiants.Identifiants
	Journal      func(string)
}

// session : connexion LDAP chiffrée et authentifiée.
type session struct {
	c    *ldap.Conn
	hote string
	lien string
}

// Collecter lit l'annuaire et renvoie la section « ad » des observations.
func Collecter(ctx context.Context, o Options) (*scan.Annuaire, error) {
	if o.Journal == nil {
		o.Journal = func(string) {}
	}
	domaine := strings.ToLower(strings.TrimSpace(o.Domaine))
	if domaine == "" {
		domaine = strings.ToLower(os.Getenv("USERDNSDOMAIN"))
	}
	if domaine == "" {
		return nil, ErrHorsDomaine
	}
	s, controleurs, err := ouvrir(ctx, domaine, o.Identifiants)
	if err != nil {
		return nil, err
	}
	defer s.c.Close()
	o.Journal(fmt.Sprintf("Annuaire %s : connexion %s chiffrée à %s, lecture seule.", domaine, strings.ToUpper(s.lien), s.hote))

	racine, err := s.recherche("", ldap.ScopeBaseObject, "(objectClass=*)",
		[]string{"defaultNamingContext", "schemaNamingContext", "domainFunctionality"}, false)
	if err != nil || len(racine) == 0 {
		return nil, fmt.Errorf("lecture de la racine de l'annuaire : %w", err)
	}
	base := racine[0].texte("defaultnamingcontext")
	schema := racine[0].texte("schemanamingcontext")
	c := Collecte{NomDomaine: domaine, Controleurs: controleurs}
	if v, err := strconv.Atoi(racine[0].texte("domainfunctionality")); err == nil {
		c.NiveauFonctionnel = &v
	}
	dom, err := s.recherche(base, ldap.ScopeBaseObject, "(objectClass=*)", AttributsDomaine, true)
	if err != nil || len(dom) == 0 {
		return nil, fmt.Errorf("lecture de l'objet domaine : %w", err)
	}
	c.Domaine = dom[0]
	if c.Utilisateurs, err = s.recherche(base, ldap.ScopeWholeSubtree, "(&(objectCategory=person)(objectClass=user))", AttributsUtilisateur, true); err != nil {
		return nil, fmt.Errorf("lecture des comptes : %w", err)
	}
	o.Journal(fmt.Sprintf("Annuaire : %d comptes utilisateurs lus.", len(c.Utilisateurs)))
	if c.Groupes, err = s.recherche(base, ldap.ScopeWholeSubtree, "(objectClass=group)", AttributsGroupe, true); err != nil {
		return nil, fmt.Errorf("lecture des groupes : %w", err)
	}
	for i := range c.Groupes {
		s.completerMembres(&c.Groupes[i])
	}
	o.Journal(fmt.Sprintf("Annuaire : %d groupes lus.", len(c.Groupes)))
	if c.Ordinateurs, err = s.recherche(base, ldap.ScopeWholeSubtree, "(objectClass=computer)", AttributsOrdinateur, true); err != nil {
		return nil, fmt.Errorf("lecture des ordinateurs : %w", err)
	}
	o.Journal(fmt.Sprintf("Annuaire : %d ordinateurs lus.", len(c.Ordinateurs)))
	if schema != "" {
		c.SchemaLAPSLegacy = s.existe(schema, "(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)")
		c.SchemaLAPSWindows = s.existe(schema, "(lDAPDisplayName=msLAPS-PasswordExpirationTime)")
	}
	a := Construire(c)
	a.Lien = s.lien
	return &a, nil
}

// ErrHorsDomaine : poste hors domaine et aucun domaine indiqué.
var ErrHorsDomaine = errors.New("poste hors domaine Active Directory : collecte de l'annuaire non applicable")

// ouvrir : découverte des contrôleurs (DNS SRV), connexion LDAPS puis repli StartTLS, liaison
// authentifiée. JAMAIS de connexion en clair : sans TLS, la collecte est abandonnée.
func ouvrir(ctx context.Context, domaine string, id *identifiants.Identifiants) (*session, []string, error) {
	_, srv, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domaine)
	if err != nil || len(srv) == 0 {
		return nil, nil, fmt.Errorf("aucun contrôleur de domaine trouvé pour %s : %w", domaine, err)
	}
	var controleurs []string
	for _, r := range srv {
		controleurs = append(controleurs, strings.TrimSuffix(r.Target, "."))
	}
	sort.Strings(controleurs)
	var derniere error
	for _, hote := range controleurs {
		for _, lien := range []string{"ldaps", "starttls"} {
			s, err := connecter(hote, lien)
			if err != nil {
				derniere = err
				continue
			}
			if err := lier(s, domaine, id); err != nil {
				s.c.Close()
				derniere = err
				continue
			}
			return s, controleurs, nil
		}
	}
	return nil, controleurs, fmt.Errorf("connexion chiffrée à l'annuaire impossible : %w", derniere)
}

func connecter(hote, lien string) (*session, error) {
	cfg := &tls.Config{ServerName: hote, MinVersion: tls.VersionTLS12}
	var c *ldap.Conn
	var err error
	if lien == "ldaps" {
		c, err = ldap.DialURL("ldaps://"+net.JoinHostPort(hote, "636"), ldap.DialWithTLSConfig(cfg),
			ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
	} else {
		c, err = ldap.DialURL("ldap://"+net.JoinHostPort(hote, "389"), ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}))
		if err == nil {
			if err = c.StartTLS(cfg); err != nil {
				c.Close()
			}
		}
	}
	if err != nil {
		return nil, err
	}
	c.SetTimeout(2 * time.Minute)
	return &session{c: c, hote: hote, lien: lien}, nil
}

// recherche paginée ; `sd` ajoute le contrôle SD_FLAGS (propriétaire + DACL seulement, lisibles par un
// utilisateur standard ; la SACL n'est jamais demandée).
func (s *session) recherche(base string, portee int, filtre string, attrs []string, sd bool) ([]Entree, error) {
	if err := verifierAttributs(attrs); err != nil {
		return nil, err
	}
	var ctrl []ldap.Control
	if sd {
		ctrl = append(ctrl, controleSDFlags{flags: 0x1 | 0x4})
	}
	req := ldap.NewSearchRequest(base, portee, ldap.NeverDerefAliases, 0, 0, false, filtre, attrs, ctrl)
	var res *ldap.SearchResult
	var err error
	if portee == ldap.ScopeBaseObject {
		res, err = s.c.Search(req)
	} else {
		res, err = s.c.SearchWithPaging(req, 500)
	}
	if err != nil {
		return nil, err
	}
	out := make([]Entree, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, versEntree(e))
	}
	return out, nil
}

func versEntree(e *ldap.Entry) Entree {
	r := Entree{DN: e.DN, Attrs: map[string][][]byte{}}
	for _, a := range e.Attributes {
		r.Attrs[strings.ToLower(a.Name)] = a.ByteValues
	}
	return r
}

// completerMembres : récupération par tranches des groupes de plus de 1 500 membres (« member;range=… »).
func (s *session) completerMembres(g *Entree) {
	for nom, vals := range g.Attrs {
		if !strings.HasPrefix(nom, "member;range=") {
			continue
		}
		membres := append([][]byte{}, vals...)
		suite := nom
		for i := 0; i < 200 && !strings.HasSuffix(suite, "-*"); i++ {
			fin, err := strconv.Atoi(suite[strings.LastIndex(suite, "-")+1:])
			if err != nil {
				break
			}
			attr := fmt.Sprintf("member;range=%d-*", fin+1)
			res, err := s.c.Search(ldap.NewSearchRequest(g.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
				"(objectClass=*)", []string{attr}, nil))
			if err != nil || len(res.Entries) == 0 || len(res.Entries[0].Attributes) == 0 {
				break
			}
			a := res.Entries[0].Attributes[0]
			membres = append(membres, a.ByteValues...)
			suite = strings.ToLower(a.Name)
		}
		delete(g.Attrs, nom)
		g.Attrs["member"] = membres
		return
	}
}

func (s *session) existe(base, filtre string) bool {
	res, err := s.c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filtre, []string{"cn"}, nil))
	return err == nil && len(res.Entries) > 0
}

// verifierAttributs : défense en profondeur, aucun attribut secret ne peut être demandé.
func verifierAttributs(attrs []string) error {
	for _, a := range attrs {
		l := strings.ToLower(a)
		for _, x := range AttributsInterdits {
			if l == x || strings.HasPrefix(l, x+";") {
				return fmt.Errorf("attribut secret refusé : %s", a)
			}
		}
	}
	return nil
}

// controleSDFlags : contrôle LDAP_SERVER_SD_FLAGS_OID (1.2.840.113556.1.4.801), valeur
// SEQUENCE { INTEGER flags } — 0x1 propriétaire, 0x4 DACL.
type controleSDFlags struct{ flags int }

func (c controleSDFlags) GetControlType() string { return "1.2.840.113556.1.4.801" }
func (c controleSDFlags) String() string         { return fmt.Sprintf("SD_FLAGS(%d)", c.flags) }
func (c controleSDFlags) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Type"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	valeur := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlags")
	valeur.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.flags), "Flags"))
	enveloppe := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Value")
	enveloppe.AppendChild(valeur)
	p.AppendChild(enveloppe)
	return p
}

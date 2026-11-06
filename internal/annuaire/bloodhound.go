package annuaire

// Export BloodHound Community Edition produit PAR L'AGENT à partir de sa propre collecte LDAP (aucun
// SharpHound) : fichiers users.json, groups.json, computers.json et domains.json au format de collecte
// v6 (« meta » + « data »), réunis dans une archive ZIP que le cabinet peut importer dans SA propre
// instance de BloodHound CE (« Upload Data »). L'export ne contient QUE ce qui a été collecté :
// appartenances, droits (ACE) et délégations ; pas de sessions ni d'administrateurs locaux.
//
// Finalité défensive : visualiser les chemins de contrôle à RÉDUIRE. Aucun secret n'y figure (la
// collecte exclut mots de passe, condensats et mots de passe LAPS).

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cacyber/agent/internal/scan"
)

// Version du format de collecte BloodHound (SharpHound v2 / BloodHound CE).
const versionFormatBH = 6

// Droits (arêtes) exportés comme ACE de l'objet cible, avec le nom attendu par BloodHound.
var droitsACE = map[string]bool{
	"GenericAll": true, "GenericWrite": true, "WriteDacl": true, "WriteOwner": true, "Owns": true,
	"AllExtendedRights": true, "ForceChangePassword": true, "AddMember": true, "AddSelf": true,
	"AddKeyCredentialLink": true,
}

// Types d'objets BloodHound.
var typesBH = map[string]string{"u": "User", "g": "Group", "c": "Computer", "d": "Domain"}

// aceBH : entrée de contrôle d'accès au format BloodHound.
type aceBH struct {
	RightName     string `json:"RightName"`
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	IsInherited   bool   `json:"IsInherited"`
}

// refBH : référence à un objet (membre de groupe, cible de délégation).
type refBH struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// collecteNonFaite : section que l'agent ne collecte pas (sessions, groupes locaux) ; déclarée
// explicitement non collectée pour que BloodHound n'en tire aucune conclusion.
type collecteNonFaite struct {
	Results       []any   `json:"Results"`
	Collected     bool    `json:"Collected"`
	FailureReason *string `json:"FailureReason"`
}

type fichierBH struct {
	Data []map[string]any `json:"data"`
	Meta struct {
		Methods int    `json:"methods"`
		Type    string `json:"type"`
		Count   int    `json:"count"`
		Version int    `json:"version"`
	} `json:"meta"`
}

// horodatageUnix : « AAAA-MM-JJ » -> secondes Unix (0 si absent ou illisible).
func horodatageUnix(d *string) int64 {
	if d == nil || *d == "" {
		return 0
	}
	t, err := time.Parse("2006-01-02", *d)
	if err != nil {
		return 0
	}
	return t.Unix()
}

// FichiersBloodHound convertit l'annuaire collecté en fichiers BloodHound CE (nom -> contenu JSON).
func FichiersBloodHound(a *scan.Annuaire) (map[string][]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("aucun annuaire à exporter")
	}
	dom := strings.ToUpper(a.Domaine.Nom)
	types := map[string]string{} // SID -> type BloodHound
	for _, n := range a.Noeuds {
		types[n.ID] = typesBH[n.T]
	}
	typeDe := func(sid string) string {
		if t, ok := types[sid]; ok && t != "" {
			return t
		}
		return "Group" // principaux bien connus (Utilisateurs authentifiés, Tout le monde…)
	}

	aces := map[string][]aceBH{}     // cible -> ACE
	membres := map[string][]refBH{}  // groupe -> membres
	deleguer := map[string][]refBH{} // compte -> cibles de délégation contrainte
	agirPour := map[string][]refBH{} // ordinateur -> principaux autorisés (délégation basée sur la ressource)
	primaire := map[string]string{}  // compte -> groupe principal (déduit : Utilisateurs / Ordinateurs du domaine)
	for _, e := range a.Aretes {
		src, typ, dst := e[0], e[1], e[2]
		switch {
		case typ == "MemberOf":
			membres[dst] = append(membres[dst], refBH{src, typeDe(src)})
		case droitsACE[typ]:
			aces[dst] = append(aces[dst], aceBH{typ, src, typeDe(src), false})
		case typ == "DCSync":
			// BloodHound représente la réplication par les deux droits étendus correspondants.
			aces[dst] = append(aces[dst], aceBH{"GetChanges", src, typeDe(src), false},
				aceBH{"GetChangesAll", src, typeDe(src), false})
		case typ == "AllowedToDelegate":
			deleguer[src] = append(deleguer[src], refBH{dst, typeDe(dst)})
		case typ == "AllowedToAct":
			agirPour[dst] = append(agirPour[dst], refBH{src, typeDe(src)})
		}
	}
	if a.Domaine.SID != "" {
		for _, n := range a.Noeuds {
			switch n.T {
			case "u":
				primaire[n.ID] = a.Domaine.SID + "-513"
			case "c":
				primaire[n.ID] = a.Domaine.SID + "-515"
				if n.DC {
					primaire[n.ID] = a.Domaine.SID + "-516"
				}
			}
		}
	}

	nomBH := func(n scan.NoeudAD) string {
		if n.T == "c" || n.T == "d" {
			return strings.ToUpper(n.N)
		}
		return strings.ToUpper(n.N) + "@" + dom
	}
	base := func(n scan.NoeudAD) map[string]any {
		p := map[string]any{
			"name": nomBH(n), "domain": dom, "domainsid": a.Domaine.SID, "samaccountname": n.N,
			"admincount": n.AdminCount, "distinguishedname": "",
		}
		if n.Actif != nil {
			p["enabled"] = *n.Actif
		}
		return p
	}
	listeOuVide := func(l []refBH) []refBH {
		if l == nil {
			return []refBH{}
		}
		return l
	}
	acesOuVide := func(id string) []aceBH {
		if l := aces[id]; l != nil {
			return l
		}
		return []aceBH{}
	}
	nonCollecte := collecteNonFaite{Results: []any{}, Collected: false}

	var users, groups, computers, domains []map[string]any
	for _, n := range a.Noeuds {
		p := base(n)
		obj := map[string]any{"ObjectIdentifier": n.ID, "Properties": p, "Aces": acesOuVide(n.ID),
			"IsDeleted": false, "IsACLProtected": false, "ContainedBy": nil}
		switch n.T {
		case "u":
			p["hasspn"], p["dontreqpreauth"], p["pwdneverexpires"] = n.SPN, n.ASREP, n.MdpSansExpiration
			p["unconstraineddelegation"] = n.DelegNC
			p["lastlogontimestamp"], p["pwdlastset"] = horodatageUnix(n.DerniereConnexion), horodatageUnix(n.MdpChange)
			obj["PrimaryGroupSID"] = primaire[n.ID]
			obj["AllowedToDelegate"] = listeOuVide(deleguer[n.ID])
			obj["SPNTargets"], obj["HasSIDHistory"] = []any{}, []any{}
			users = append(users, obj)
		case "g":
			obj["Members"] = listeOuVide(membres[n.ID])
			groups = append(groups, obj)
		case "c":
			p["unconstraineddelegation"], p["operatingsystem"], p["isdc"] = n.DelegNC, n.OS, n.DC
			p["lastlogontimestamp"], p["pwdlastset"] = horodatageUnix(n.DerniereConnexion), horodatageUnix(n.MdpChange)
			obj["PrimaryGroupSID"] = primaire[n.ID]
			obj["AllowedToDelegate"] = listeOuVide(deleguer[n.ID])
			obj["AllowedToAct"] = listeOuVide(agirPour[n.ID])
			obj["HasSIDHistory"] = []any{}
			obj["Sessions"], obj["PrivilegedSessions"], obj["RegistrySessions"] = nonCollecte, nonCollecte, nonCollecte
			obj["LocalGroups"], obj["UserRights"] = []any{}, []any{}
			computers = append(computers, obj)
		case "d":
			if a.Domaine.NiveauFonctionnel != nil {
				p["functionallevel"] = *a.Domaine.NiveauFonctionnel
			}
			obj["Trusts"], obj["Links"], obj["ChildObjects"] = []any{}, []any{}, []any{}
			domains = append(domains, obj)
		}
	}

	res := map[string][]byte{}
	for nom, donnees := range map[string][]map[string]any{"users": users, "groups": groups, "computers": computers, "domains": domains} {
		if donnees == nil {
			donnees = []map[string]any{}
		}
		sort.Slice(donnees, func(i, j int) bool {
			return donnees[i]["ObjectIdentifier"].(string) < donnees[j]["ObjectIdentifier"].(string)
		})
		var f fichierBH
		f.Data = donnees
		f.Meta.Type, f.Meta.Count, f.Meta.Version = nom, len(donnees), versionFormatBH
		b, err := json.MarshalIndent(f, "", " ")
		if err != nil {
			return nil, err
		}
		res[nom+".json"] = b
	}
	return res, nil
}

var rxNomFichier = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// ExporterBloodHound écrit l'archive `bloodhound-<domaine>-<AAAAMMJJ-HHMM>.zip` dans `dossier` (le
// dossier des journaux remis au client) et renvoie son chemin.
func ExporterBloodHound(a *scan.Annuaire, dossier string, t time.Time) (string, error) {
	fichiers, err := FichiersBloodHound(a)
	if err != nil {
		return "", err
	}
	dom := strings.Trim(rxNomFichier.ReplaceAllString(strings.ToLower(a.Domaine.Nom), "-"), "-")
	if dom == "" {
		dom = "domaine"
	}
	chemin := filepath.Join(dossier, fmt.Sprintf("bloodhound-%s-%s.zip", dom, t.Format("20060102-1504")))
	f, err := os.OpenFile(chemin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	z := zip.NewWriter(f)
	prefixe := t.Format("20060102150405") + "_"
	noms := make([]string, 0, len(fichiers))
	for n := range fichiers {
		noms = append(noms, n)
	}
	sort.Strings(noms)
	for _, n := range noms {
		w, err := z.CreateHeader(&zip.FileHeader{Name: prefixe + n, Method: zip.Deflate, Modified: t})
		if err != nil {
			_ = f.Close()
			return "", err
		}
		if _, err := w.Write(fichiers[n]); err != nil {
			_ = f.Close()
			return "", err
		}
	}
	if err := z.Close(); err != nil {
		_ = f.Close()
		return "", err
	}
	return chemin, f.Close()
}

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cacyber/agent/internal/outils"
)

// RequetesOsquery : SEULES requêtes exécutées par osquery sur le poste local (SELECT uniquement,
// liste blanche figée, vérifiée par les tests et avant chaque exécution).
var RequetesOsquery = map[string]string{
	"version":   "select version from osquery_info",
	"bitlocker": "select drive_letter, protection_status from bitlocker_info",
	"securite":  "select firewall, autoupdate, antivirus, user_account_control from windows_security_center",
	"programmes": "select count(*) as n from programs",
}

var rxSelect = regexp.MustCompile(`(?i)^\s*select\s[^;]*$`)

// RequeteLectureSeule : une seule instruction SELECT, sans point-virgule ni instruction d'écriture.
func RequeteLectureSeule(q string) error {
	l := strings.ToLower(q)
	if !rxSelect.MatchString(q) || strings.Contains(l, "insert") || strings.Contains(l, "update ") ||
		strings.Contains(l, "delete") || strings.Contains(l, "attach") || strings.Contains(l, "pragma") {
		return fmt.Errorf("requête osquery refusée : %q", q)
	}
	return nil
}

// CollecterOsquery exécute les requêtes de la liste blanche avec le binaire VÉRIFIÉ (signature de
// l'éditeur contrôlée par outils.Preparer) et renvoie la section « osquery » des observations.
func CollecterOsquery(ctx context.Context, x *outils.Executable) (*Osquery, error) {
	res := map[string][]map[string]string{}
	for nom, q := range RequetesOsquery {
		if err := RequeteLectureSeule(q); err != nil {
			return nil, err
		}
		c, annuler := context.WithTimeout(ctx, 90*time.Second)
		cmd := x.Commande(c, "--json", "--disable_extensions", q)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		annuler()
		if err != nil {
			continue // table indisponible (ex. bitlocker_info sans droits) : section partielle
		}
		var lignes []map[string]string
		if json.Unmarshal(out.Bytes(), &lignes) == nil {
			res[nom] = lignes
		}
	}
	return AnalyserOsquery(res)
}

// AnalyserOsquery met en forme les résultats bruts (sortie JSON d'osqueryi : valeurs textuelles).
func AnalyserOsquery(res map[string][]map[string]string) (*Osquery, error) {
	v := res["version"]
	if len(v) == 0 {
		return nil, errors.New("osquery : aucune réponse")
	}
	o := &Osquery{Version: v[0]["version"]}
	for _, l := range res["bitlocker"] {
		o.BitLocker = append(o.BitLocker, VolumeBitLocker{Lecteur: l["drive_letter"], Protection: l["protection_status"] == "1"})
	}
	if s := res["securite"]; len(s) > 0 {
		o.PareFeu, o.MisesAJour, o.Antivirus, o.ControleCompte = s[0]["firewall"], s[0]["autoupdate"], s[0]["antivirus"], s[0]["user_account_control"]
	}
	if p := res["programmes"]; len(p) > 0 {
		o.NbProgrammes, _ = strconv.Atoi(p[0]["n"])
	}
	return o, nil
}

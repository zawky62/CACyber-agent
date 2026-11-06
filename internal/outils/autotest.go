package outils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ResultatTest : résultat d'un contrôle de bon fonctionnement.
type ResultatTest struct {
	Outil  string `json:"outil"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Rapport : bilan remis au client (journal local) après installation et auto-test.
type Rapport struct {
	Date       string         `json:"date"`
	Composants []EtatOutil    `json:"composants"`
	Tests      []ResultatTest `json:"tests"`
	Pret       bool           `json:"moteur_pret"`
	Message    string         `json:"message"`
}

var rxPortOuvert = regexp.MustCompile(`<port protocol="tcp" portid="(\d+)"><state state="open"`)

// AutoTest exécute des contrôles NON INTRUSIFS, limités au poste lui-même (127.0.0.1) :
//   - Nmap : mini-scan « connect » de quelques ports de 127.0.0.1 (aucun autre hôte) ;
//   - osquery : requête en lecture seule « select name, version from programs limit 5 » ;
//   - Nuclei : version, puis validation des modèles de la liste blanche (aucune requête réseau).
//
// « Moteur de scan prêt » dès que Nmap OU le scanner natif est disponible ; osquery et Nuclei
// enrichissent la collecte mais ne la conditionnent pas.
func (g *Gestionnaire) AutoTest(ctx context.Context, nmapExplicite string) Rapport {
	r := Rapport{Date: time.Now().Format(time.RFC3339)}
	r.Composants = append(r.Composants, g.Etat()...)

	// Nmap
	if x, err := PreparerNmap(nmapExplicite); err != nil {
		r.Tests = append(r.Tests, ResultatTest{"nmap", false, err.Error() + " — scanner natif utilisé (connexions TCP)."})
	} else {
		r.Composants = append(r.Composants, x.Etat("installation du poste, signature vérifiée"))
		r.Tests = append(r.Tests, testNmap(ctx, x))
		x.Fermer()
	}
	// osquery
	if x, err := g.Preparer(Osquery); err != nil {
		r.Tests = append(r.Tests, ResultatTest{"osquery", false, err.Error()})
	} else {
		r.Tests = append(r.Tests, testOsquery(ctx, x))
		x.Fermer()
	}
	// Nuclei
	if x, err := g.Preparer(Nuclei); err != nil {
		r.Tests = append(r.Tests, ResultatTest{"nuclei", false, err.Error()})
	} else {
		r.Tests = append(r.Tests, testNuclei(ctx, x, g.DossierModeles()))
		x.Fermer()
	}
	r.Pret = true // le scanner natif intégré garantit toujours un moteur de découverte
	echecs := []string{}
	for _, t := range r.Tests {
		if !t.OK {
			echecs = append(echecs, t.Outil)
		}
	}
	if len(echecs) == 0 {
		r.Message = "Moteur de scan prêt."
	} else {
		r.Message = "Moteur de scan prêt (mode réduit : " + strings.Join(echecs, ", ") + " indisponible(s))."
	}
	return r
}

func executer(ctx context.Context, x *Executable, delai time.Duration, args ...string) ([]byte, []byte, error) {
	c, annuler := context.WithTimeout(ctx, delai)
	defer annuler()
	cmd := x.Commande(c, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// ArgumentsAutoTestNmap : arguments FIGÉS du mini-scan de contrôle (127.0.0.1 uniquement).
var ArgumentsAutoTestNmap = []string{"--unprivileged", "-sT", "-Pn", "-T3", "--max-retries", "1",
	"--host-timeout", "60s", "-p", "135,445,3389,8000,8443", "-oX", "-", "127.0.0.1"}

func testNmap(ctx context.Context, x *Executable) ResultatTest {
	out, errb, err := executer(ctx, x, 2*time.Minute, ArgumentsAutoTestNmap...)
	if err != nil {
		return ResultatTest{"nmap", false, fmt.Sprintf("mini-scan de 127.0.0.1 en échec : %v %s", err, strings.TrimSpace(string(errb)))}
	}
	if !bytes.Contains(out, []byte("<nmaprun")) {
		return ResultatTest{"nmap", false, "sortie XML absente"}
	}
	var ports []string
	for _, m := range rxPortOuvert.FindAllSubmatch(out, -1) {
		ports = append(ports, string(m[1]))
	}
	mode := "mode connect, sans Npcap ni droits administrateur"
	return ResultatTest{"nmap", true, fmt.Sprintf("mini-scan de 127.0.0.1 réussi (%s) : %d port(s) ouvert(s) %s",
		mode, len(ports), strings.Join(ports, ","))}
}

// RequeteAutoTestOsquery : requête en lecture seule du contrôle.
const RequeteAutoTestOsquery = "select name, version from programs limit 5"

func testOsquery(ctx context.Context, x *Executable) ResultatTest {
	out, errb, err := executer(ctx, x, 90*time.Second, "--json", "--disable_extensions", RequeteAutoTestOsquery)
	if err != nil {
		return ResultatTest{"osquery", false, fmt.Sprintf("requête en échec : %v %s", err, strings.TrimSpace(string(errb)))}
	}
	var lignes []map[string]string
	if err := json.Unmarshal(out, &lignes); err != nil {
		return ResultatTest{"osquery", false, "sortie JSON illisible"}
	}
	return ResultatTest{"osquery", true, fmt.Sprintf("inventaire en lecture seule opérationnel (%d logiciels lus)", len(lignes))}
}

var rxVersionNuclei = regexp.MustCompile(`Engine Version:\s*v?([\d.]+)`)

func testNuclei(ctx context.Context, x *Executable, modeles string) ResultatTest {
	out, errb, err := executer(ctx, x, time.Minute, "-version", "-duc")
	tout := string(out) + string(errb)
	if err != nil {
		return ResultatTest{"nuclei", false, "version illisible : " + err.Error()}
	}
	v := "?"
	if m := rxVersionNuclei.FindStringSubmatch(tout); m != nil {
		v = m[1]
	}
	_, errb, err = executer(ctx, x, 2*time.Minute, ArgumentsValidationNuclei(modeles)...)
	if err != nil {
		return ResultatTest{"nuclei", false, fmt.Sprintf("validation des modèles en échec : %v %s", err, derniereLigne(string(errb)))}
	}
	return ResultatTest{"nuclei", true, fmt.Sprintf("moteur %s ; %d modèles de la liste blanche validés (signés, non intrusifs)", v, len(ModelesNuclei))}
}

// ArgumentsValidationNuclei : validation hors ligne des modèles (aucune cible, aucune requête).
func ArgumentsValidationNuclei(modeles string) []string {
	return []string{"-duc", "-ni", "-dut", "-validate", "-t", modeles,
		"-etags", strings.Join(EtiquettesExclues, ","), "-ept", strings.Join(TypesExclus, ","), "-nc"}
}

func derniereLigne(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l[len(l)-1])
}

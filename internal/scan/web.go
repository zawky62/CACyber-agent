package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Contrôles web NATIFS, passifs et non intrusifs (remplacent les 9 modèles Nuclei de la liste
// blanche, retirés car le binaire Nuclei n'est pas signé et est classé « hacktool » par des EDR) :
//
//   - négociation TLS : suites de chiffrement faibles acceptées (offre limitée aux suites
//     faibles, au plus 6 poignées de main par port) ; versions TLS déjà relevées par le scanner ;
//   - certificat présenté : expiré, auto-signé, nom ne correspondant pas à l'équipement, autorité
//     non reconnue par le magasin du système ;
//   - UNE requête « GET / » sans redirection ni corps : en-têtes de sécurité absents (HSTS, CSP,
//     X-Frame-Options, X-Content-Type-Options, Referrer-Policy) et technologies annoncées
//     (en-têtes Server / X-Powered-By, balise HTML « generator »).
//
// Aucune charge utile, aucun formulaire, aucune tentative d'authentification, aucun chemin deviné.

// Certificat : constats sur le certificat présenté par un service TLS.
type Certificat struct {
	Sujet         string `json:"sujet,omitempty"`
	Emetteur      string `json:"emetteur,omitempty"`
	ExpireLe      string `json:"expire_le,omitempty"` // AAAA-MM-JJ
	Expire        bool   `json:"expire"`
	AutoSigne     bool   `json:"auto_signe"`
	NomIncorrect  bool   `json:"nom_incorrect"`
	NonApprouve   bool   `json:"non_approuve"`
	JoursRestants int    `json:"jours_restants"`
}

// ControleWeb : résultat des contrôles passifs d'un service web (un hôte, un port).
type ControleWeb struct {
	IP                  string      `json:"ip"`
	Port                int         `json:"port"`
	HTTPS               bool        `json:"https"`
	Statut              int         `json:"statut,omitempty"` // code HTTP de « GET / »
	ChiffrementsFaibles []string    `json:"chiffrements_faibles,omitempty"`
	Certificat          *Certificat `json:"certificat,omitempty"`
	HSTS                *bool       `json:"hsts,omitempty"`
	EntetesManquants    []string    `json:"entetes_manquants,omitempty"`
	Technologies        []string    `json:"technologies,omitempty"`
}

// PortsWeb : ports examinés quand le service n'est pas identifié comme web.
var PortsWeb = map[int]bool{80: true, 443: true, 8000: true, 8008: true, 8080: true, 8081: true, 8443: true,
	8888: true, 5000: true, 5001: true, 9443: true}

// EntetesSecurite : en-têtes attendus d'une interface web (HSTS traité à part, HTTPS seulement).
var EntetesSecurite = []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"}

const delaiWeb = 6 * time.Second

func estWeb(p Port) bool {
	s := strings.ToLower(p.Service)
	return PortsWeb[p.Port] || strings.Contains(s, "http") || strings.Contains(s, "https") || strings.Contains(s, "ssl")
}

// ControlerWeb examine les services web des hôtes (4 hôtes au plus en parallèle, ports en séquence).
func ControlerWeb(ctx context.Context, hotes []Hote) []ControleWeb {
	var (
		mu  sync.Mutex
		res []ControleWeb
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, 4)
	for _, h := range hotes {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			for _, p := range h.Ports {
				if ctx.Err() != nil || !estWeb(p) {
					continue
				}
				c := ControlerService(ctx, h.IP, h.Nom, p.Port)
				if c != nil {
					mu.Lock()
					res = append(res, *c)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool {
		if res[i].IP != res[j].IP {
			return res[i].IP < res[j].IP
		}
		return res[i].Port < res[j].Port
	})
	return res
}

// ControlerService : contrôles passifs d'un service (TLS si le port parle TLS, puis « GET / »).
func ControlerService(ctx context.Context, ip, nom string, port int) *ControleWeb {
	adr := net.JoinHostPort(ip, strconv.Itoa(port))
	c := &ControleWeb{IP: ip, Port: port}
	if cert, inter, ok := certificatPresente(ctx, adr); ok {
		c.HTTPS = true
		c.Certificat = analyserCertificat(cert, inter, ip, nom, time.Now())
		c.ChiffrementsFaibles = chiffrementsFaibles(ctx, adr)
	}
	schema := map[bool]string{true: "https", false: "http"}[c.HTTPS]
	en, statut, corps, err := requeteAccueil(ctx, fmt.Sprintf("%s://%s/", schema, adr))
	if err != nil && !c.HTTPS {
		return nil // ni TLS ni HTTP : pas un service web
	}
	if err == nil {
		c.Statut = statut
		c.EntetesManquants, c.HSTS = entetesManquants(en, c.HTTPS)
		c.Technologies = technologies(en, corps)
	}
	return c
}

func configTLS(min, max uint16, suites []uint16) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // le certificat est analysé à part : la poignée de main doit aboutir
		MinVersion:         min, MaxVersion: max, CipherSuites: suites,
	}
}

func poigneeDeMain(ctx context.Context, adr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: delaiWeb}, Config: cfg}
	ctx, annuler := context.WithTimeout(ctx, delaiWeb)
	defer annuler()
	c, err := d.DialContext(ctx, "tcp", adr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

func certificatPresente(ctx context.Context, adr string) (*x509.Certificate, []*x509.Certificate, bool) {
	c, err := poigneeDeMain(ctx, adr, configTLS(tls.VersionTLS10, tls.VersionTLS13, nil))
	if err != nil {
		return nil, nil, false
	}
	defer c.Close()
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, false
	}
	return certs[0], certs[1:], true
}

// analyserCertificat : expiration, auto-signature, correspondance du nom, autorité reconnue.
func analyserCertificat(cert *x509.Certificate, inter []*x509.Certificate, ip, nom string, maintenant time.Time) *Certificat {
	r := &Certificat{
		Sujet: cert.Subject.CommonName, Emetteur: cert.Issuer.CommonName, ExpireLe: cert.NotAfter.UTC().Format("2006-01-02"),
		Expire:        maintenant.After(cert.NotAfter),
		JoursRestants: int(cert.NotAfter.Sub(maintenant).Hours() / 24),
	}
	// Auto-signé : émetteur = sujet ET signature vérifiable par la clé du certificat lui-même
	// (vérification directe : CheckSignatureFrom exigerait l'extension « autorité »).
	r.AutoSigne = cert.Issuer.String() == cert.Subject.String() &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	r.NomIncorrect = cert.VerifyHostname(ip) != nil && (nom == "" || cert.VerifyHostname(nom) != nil)
	pool := x509.NewCertPool()
	for _, c := range inter {
		pool.AddCert(c)
	}
	_, err := cert.Verify(x509.VerifyOptions{Intermediates: pool, CurrentTime: maintenant.Add(-time.Second)})
	var inconnue x509.UnknownAuthorityError
	r.NonApprouve = err != nil && (errors.As(err, &inconnue) || r.AutoSigne)
	return r
}

// chiffrementsFaibles : n'offre QUE des suites jugées faibles (RC4, 3DES, CBC-SHA1 sans PFS…) et
// relève celles que le serveur accepte (une suite retirée de l'offre après chaque succès).
func chiffrementsFaibles(ctx context.Context, adr string) []string {
	var offre []uint16
	for _, s := range tls.InsecureCipherSuites() {
		offre = append(offre, s.ID)
	}
	for _, s := range tls.CipherSuites() { // suites « sûres » pour Go mais sans confidentialité persistante
		if strings.HasPrefix(s.Name, "TLS_RSA_") {
			offre = append(offre, s.ID)
		}
	}
	var acceptees []string
	for i := 0; i < 6 && len(offre) > 0 && ctx.Err() == nil; i++ {
		c, err := poigneeDeMain(ctx, adr, configTLS(tls.VersionTLS10, tls.VersionTLS12, offre))
		if err != nil {
			break
		}
		suite := c.ConnectionState().CipherSuite
		_ = c.Close()
		acceptees = append(acceptees, tls.CipherSuiteName(suite))
		offre = retirer(offre, suite)
	}
	sort.Strings(acceptees)
	return acceptees
}

func retirer(l []uint16, x uint16) []uint16 {
	res := l[:0:0]
	for _, v := range l {
		if v != x {
			res = append(res, v)
		}
	}
	return res
}

// requeteAccueil : UNE requête GET / (aucune redirection suivie, corps lu sur 64 Kio au plus).
func requeteAccueil(ctx context.Context, url string) (http.Header, int, []byte, error) {
	cl := &http.Client{
		Timeout:       delaiWeb,
		Transport:     &http.Transport{TLSClientConfig: configTLS(tls.VersionTLS10, tls.VersionTLS13, nil), DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("User-Agent", "CACyber-Agent (audit de securite en lecture seule, sous mandat)")
	rep, err := cl.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer rep.Body.Close()
	corps, _ := io.ReadAll(io.LimitReader(rep.Body, 64<<10))
	return rep.Header, rep.StatusCode, corps, nil
}

// entetesManquants : en-têtes de sécurité absents ; HSTS seulement pertinent en HTTPS.
func entetesManquants(h http.Header, https bool) ([]string, *bool) {
	var manquants []string
	for _, e := range EntetesSecurite {
		if e == "X-Frame-Options" && strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
			continue // protection équivalente par CSP
		}
		if h.Get(e) == "" {
			manquants = append(manquants, e)
		}
	}
	var hsts *bool
	if https {
		v := h.Get("Strict-Transport-Security") != ""
		hsts = &v
		if !v {
			manquants = append([]string{"Strict-Transport-Security"}, manquants...)
		}
	}
	return manquants, hsts
}

var rxGenerateur = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']{1,80})["']`)

// technologies annoncées par le serveur (en-têtes et balise « generator »), dédoublonnées.
func technologies(h http.Header, corps []byte) []string {
	vus := map[string]bool{}
	var res []string
	ajout := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && len(s) <= 120 && !vus[strings.ToLower(s)] {
			vus[strings.ToLower(s)] = true
			res = append(res, s)
		}
	}
	for _, e := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
		ajout(h.Get(e))
	}
	if m := rxGenerateur.FindSubmatch(corps); m != nil {
		ajout(string(m[1]))
	}
	return res
}

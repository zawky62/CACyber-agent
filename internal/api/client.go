// Package api dialogue avec le serveur CACyber.
//
//   - Appairage (application principale, HTTPS) : le code à usage unique et une CSR générée
//     localement sont échangés contre un certificat client lié au site et au mandat signé.
//   - Ensuite, tout passe par l'écoute mTLS des agents : le certificat client est présenté en TLS
//     ET chaque requête est signée par la clé de l'agent (preuve de possession, anti-rejeu).
//
// Le serveur ne renvoie jamais de commande à exécuter : uniquement un contexte (site, client) et
// une politique bornée, recoupée par la liste blanche compilée de l'agent.
package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"cacyber/agent/internal/etat"
	"cacyber/agent/internal/scan"
)

// ----------------------------------------------------------------------------- signature

// MessageASigner reproduit exactement backend/app/pki.py:message_a_signer :
// « MÉTHODE\nCHEMIN\nHORODATAGE\nsha256hex(corps) ». Le chemin ne comprend pas la requête (?…).
func MessageASigner(methode, chemin, horodatage string, corps []byte) []byte {
	h := sha256.Sum256(corps)
	return []byte(strings.Join([]string{strings.ToUpper(methode), chemin, horodatage, hex.EncodeToString(h[:])}, "\n"))
}

// Signer : ECDSA P-256 / SHA-256, signature ASN.1 DER encodée en base64.
func Signer(cle *ecdsa.PrivateKey, message []byte) (string, error) {
	h := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, cle, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ----------------------------------------------------------------------------- appairage

// ReponseEnrolement : ce que renvoie POST /agent/v1/enrolement.
type ReponseEnrolement struct {
	AgentID    string         `json:"agent_id"`
	Certificat string         `json:"certificat"`
	CA         string         `json:"ca"`
	ExpireLe   string         `json:"expire_le"`
	URLMTLS    string         `json:"url_mtls"`
	Site       string         `json:"site"`
	SIRET      string         `json:"siret"`
	Client     string         `json:"client"`
	Cabinet    string         `json:"cabinet"`
	Politique  scan.Politique `json:"politique"`
}

// ErreurServeur : réponse d'erreur du serveur, avec son message lisible.
type ErreurServeur struct {
	Statut  int
	Message string
}

func (e *ErreurServeur) Error() string { return fmt.Sprintf("serveur (%d) : %s", e.Statut, e.Message) }

func lireErreur(resp *http.Response) error {
	corps, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var d struct {
		Detail any `json:"detail"`
	}
	msg := strings.TrimSpace(string(corps))
	if json.Unmarshal(corps, &d) == nil && d.Detail != nil {
		switch v := d.Detail.(type) {
		case string:
			msg = v
		case map[string]any:
			if m, ok := v["message"].(string); ok {
				msg = m
			}
		default:
			b, _ := json.Marshal(v)
			msg = string(b)
		}
	}
	return &ErreurServeur{Statut: resp.StatusCode, Message: msg}
}

// EstLocal : vrai si l'URL désigne ce poste (développement / démonstration).
func EstLocal(u *url.URL) bool {
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// VerifierURLServeur refuse le HTTP en clair, sauf vers ce poste ou en mode --dev.
func VerifierURLServeur(brut string, dev bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(brut, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("adresse du serveur invalide : %q", brut)
	}
	if u.Scheme == "http" && !EstLocal(u) && !dev {
		return nil, errors.New("connexion non chiffrée refusée : utilisez https:// (ou --dev en laboratoire)")
	}
	return u, nil
}

// Enroler génère la clé et la CSR, présente le code d'appairage et enregistre l'identité reçue.
//
// Confiance dans la CA renvoyée : elle n'est acceptée que si l'appairage lui-même a eu lieu sur
// un canal authentifié (HTTPS vérifié par le magasin de certificats du système) ou vers ce poste
// (localhost / --dev). Si --ca est fourni, la CA renvoyée doit lui être identique (épinglage).
func Enroler(serveur *url.URL, code, version string, caEpinglee []byte, dev bool, d *etat.Dossier) (*etat.Etat, *ReponseEnrolement, error) {
	if serveur.Scheme == "http" && !EstLocal(serveur) && !dev {
		return nil, nil, errors.New("appairage refusé sur un canal non chiffré")
	}
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	nomHote, _ := os.Hostname()
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "cacyber-agent", Organization: []string{"CACyber"}},
	}, cle)
	if err != nil {
		return nil, nil, err
	}
	corps, _ := json.Marshal(map[string]string{
		"code":     code,
		"csr":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"nom_hote": nomHote,
		"systeme":  runtime.GOOS + "/" + runtime.GOARCH,
		"version":  version,
	})
	cli := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}}
	resp, err := cli.Post(serveur.String()+"/agent/v1/enrolement", "application/json", bytes.NewReader(corps))
	if err != nil {
		return nil, nil, fmt.Errorf("serveur injoignable : %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, lireErreur(resp)
	}
	var r ReponseEnrolement
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, nil, fmt.Errorf("réponse d'appairage illisible : %w", err)
	}
	if caEpinglee != nil && strings.TrimSpace(string(caEpinglee)) != strings.TrimSpace(r.CA) {
		return nil, nil, errors.New("la CA renvoyée par le serveur ne correspond pas à la CA épinglée (--ca) : appairage annulé")
	}
	// Contrôle de cohérence : le certificat reçu porte bien NOTRE clé publique et émane de la CA.
	if err := verifierCertificat(r.Certificat, r.CA, &cle.PublicKey); err != nil {
		return nil, nil, err
	}
	if r.URLMTLS == "" {
		return nil, nil, errors.New("le serveur n'a pas indiqué l'adresse de l'écoute mTLS")
	}
	cleDER, _ := x509.MarshalECPrivateKey(cle)
	e := &etat.Etat{AgentID: r.AgentID, Serveur: serveur.String(), URLMTLS: strings.TrimRight(r.URLMTLS, "/"),
		Site: r.Site, SIRET: r.SIRET, Client: r.Client, Cabinet: r.Cabinet, ExpireLe: r.ExpireLe}
	err = d.Enregistrer(e, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cleDER}),
		[]byte(r.Certificat), []byte(r.CA))
	return e, &r, err
}

func verifierCertificat(certPEM, caPEM string, pub *ecdsa.PublicKey) error {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return errors.New("certificat reçu illisible")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if p, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !p.Equal(pub) {
		return errors.New("le certificat reçu ne correspond pas à la clé générée")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return errors.New("CA reçue illisible")
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return fmt.Errorf("certificat non émis par la CA du serveur : %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------- client mTLS

// Client : session authentifiée d'un agent relié.
type Client struct {
	etat *etat.Etat
	cle  *ecdsa.PrivateKey
	http *http.Client
	base string
}

// NouveauClient charge l'identité et prépare la connexion mTLS (TLS 1.2 minimum, CA du serveur
// seule autorité acceptée, certificat client présenté).
func NouveauClient(e *etat.Etat, d *etat.Dossier) (*Client, error) {
	paire, err := tls.LoadX509KeyPair(d.CheminCertificat(), d.CheminCle())
	if err != nil {
		return nil, fmt.Errorf("identité de l'agent illisible : %w", err)
	}
	caPEM, err := os.ReadFile(d.CheminCA())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA du serveur illisible")
	}
	cle, ok := paire.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("clé de l'agent inattendue (ECDSA P-256 attendue)")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{paire}},
		Proxy:           http.ProxyFromEnvironment,
	}
	return &Client{etat: e, cle: cle, base: e.URLMTLS, http: &http.Client{Timeout: 120 * time.Second, Transport: tr}}, nil
}

// requete envoie une requête signée et décode la réponse JSON dans `sortie`.
func (c *Client) requete(methode, chemin, requete string, corps []byte, sortie any) error {
	horo := strconv.FormatInt(time.Now().Unix(), 10)
	sig, err := Signer(c.cle, MessageASigner(methode, chemin, horo, corps))
	if err != nil {
		return err
	}
	cible := c.base + chemin
	if requete != "" {
		cible += "?" + requete
	}
	req, err := http.NewRequest(methode, cible, bytes.NewReader(corps))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CAC-Agent", c.etat.AgentID)
	req.Header.Set("X-CAC-Horodatage", horo)
	req.Header.Set("X-CAC-Signature", sig)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("écoute des agents injoignable (%s) : %w", c.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return lireErreur(resp)
	}
	if sortie == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(sortie)
}

// Moi : contexte du site et validité du mandat (GET /agent/v1/moi).
type Moi struct {
	AgentID      string         `json:"agent_id"`
	Site         string         `json:"site"`
	SIRET        string         `json:"siret"`
	Client       string         `json:"client"`
	Cabinet      string         `json:"cabinet"`
	MandatValide bool           `json:"mandat_valide"`
	MandatFin    string         `json:"mandat_fin"`
	Politique    scan.Politique `json:"politique"`
}

func (c *Client) Moi() (*Moi, error) {
	var m Moi
	return &m, c.requete(http.MethodGet, "/agent/v1/moi", "", nil, &m)
}

// DebutScan : réponse de POST /agent/v1/scans.
type DebutScan struct {
	ScanID    string         `json:"scan_id"`
	Politique scan.Politique `json:"politique"`
	Mandat    string         `json:"mandat"`
}

// DemarrerScan demande l'ouverture d'un scan ; le serveur vérifie le mandat avant d'accepter.
func (c *Client) DemarrerScan(mode string) (*DebutScan, error) {
	var r DebutScan
	return &r, c.requete(http.MethodPost, "/agent/v1/scans", "mode="+url.QueryEscape(mode), nil, &r)
}

// Evenement : ligne du journal lisible du scan.
type Evenement struct {
	Etape       int    `json:"etape"`
	Type        string `json:"type"`
	Texte       string `json:"texte"`
	Progression *int   `json:"progression,omitempty"`
}

// EnvoyerEvenements transmet des lignes de journal (200 au plus par appel).
func (c *Client) EnvoyerEvenements(scanID string, evs []Evenement) error {
	for len(evs) > 0 {
		n := min(len(evs), 200)
		corps, _ := json.Marshal(map[string]any{"evenements": evs[:n]})
		if err := c.requete(http.MethodPost, "/agent/v1/scans/"+url.PathEscape(scanID)+"/evenements", "", corps, nil); err != nil {
			return err
		}
		evs = evs[n:]
	}
	return nil
}

// Bilan : réponse du serveur après analyse des observations.
type Bilan struct {
	Note      string `json:"note"`
	Score     int    `json:"score"`
	Empreinte string `json:"empreinte"`
	Constats  int    `json:"constats"`
	Message   string `json:"message"`
}

// EnvoyerResultats transmet les observations brutes ; le serveur renvoie la note calculée.
func (c *Client) EnvoyerResultats(scanID string, obs *scan.Observations) (*Bilan, []byte, error) {
	corps, err := json.Marshal(obs)
	if err != nil {
		return nil, nil, err
	}
	var b Bilan
	err = c.requete(http.MethodPost, "/agent/v1/scans/"+url.PathEscape(scanID)+"/resultats", "", corps, &b)
	return &b, corps, err
}

// Package api dialogue avec le serveur CACyber (fonctions Supabase), en HTTPS uniquement.
//
//   - Appairage : une paire de clés ECDSA P-256 est générée SUR LE POSTE (la clé privée ne le quitte
//     jamais, elle est protégée par DPAPI) ; le code à usage unique et la clé PUBLIQUE sont envoyés,
//     dans une requête signée par la clé privée (preuve de possession).
//   - Ensuite, CHAQUE requête est signée : méthode, chemin, horodatage, nonce unique et SHA-256 du
//     corps. Le serveur refuse toute requête modifiée, rejouée ou hors fenêtre de ±5 minutes.
//     (Remplace le TLS mutuel, impossible derrière le relais HTTPS des fonctions.)
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

// MessageASigner reproduit exactement supabase/functions/_shared/signature_agent.ts :
// « MÉTHODE\nCHEMIN\nHORODATAGE\nNONCE\nsha256hex(corps) ». Le chemin ne comprend pas la requête (?…).
func MessageASigner(methode, chemin, horodatage, nonce string, corps []byte) []byte {
	h := sha256.Sum256(corps)
	return []byte(strings.Join([]string{strings.ToUpper(methode), chemin, horodatage, nonce, hex.EncodeToString(h[:])}, "\n"))
}

// NouveauNonce : 24 octets aléatoires en base64url (32 caractères), à usage unique (anti-rejeu).
func NouveauNonce() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err) // générateur aléatoire du système indisponible : rien de sûr n'est possible
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// entetesSignes calcule les en-têtes d'authentification d'une requête.
func entetesSignes(cle *ecdsa.PrivateKey, methode, chemin string, corps []byte) (map[string]string, error) {
	horo := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := NouveauNonce()
	sig, err := Signer(cle, MessageASigner(methode, chemin, horo, nonce, corps))
	if err != nil {
		return nil, err
	}
	return map[string]string{"X-CAC-Horodatage": horo, "X-CAC-Nonce": nonce, "X-CAC-Signature": sig}, nil
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
	ExpireLe   string         `json:"expire_le"`
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

// Enroler génère la paire de clés, présente le code d'appairage avec la clé publique (requête signée
// par la clé privée : preuve de possession) et enregistre l'identité reçue.
//
// Le serveur est authentifié par HTTPS (magasin de certificats du système). `caEpinglee` est conservé
// pour compatibilité de l'interface ; il n'est plus utilisé (plus d'autorité de certification interne).
func Enroler(serveur *url.URL, code, version string, caEpinglee []byte, dev bool, d *etat.Dossier) (*etat.Etat, *ReponseEnrolement, error) {
	_ = caEpinglee
	if serveur.Scheme == "http" && !EstLocal(serveur) && !dev {
		return nil, nil, errors.New("appairage refusé sur un canal non chiffré")
	}
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&cle.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	nomHote, _ := os.Hostname()
	corps, _ := json.Marshal(map[string]string{
		"code":         code,
		"cle_publique": base64.StdEncoding.EncodeToString(spki),
		"nom_hote":     nomHote,
		"systeme":      runtime.GOOS + "/" + runtime.GOARCH,
		"version":      version,
	})
	const chemin = "/agent/v1/enrolement"
	h, err := entetesSignes(cle, http.MethodPost, chemin, corps)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, serveur.String()+chemin, bytes.NewReader(corps))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := clientHTTP(30 * time.Second).Do(req)
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
	if r.AgentID == "" {
		return nil, nil, errors.New("réponse d'appairage incomplète")
	}
	cleDER, _ := x509.MarshalECPrivateKey(cle)
	e := &etat.Etat{AgentID: r.AgentID, Serveur: serveur.String(), Site: r.Site, SIRET: r.SIRET, Client: r.Client,
		Cabinet: r.Cabinet, ExpireLe: r.ExpireLe}
	err = d.Enregistrer(e, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cleDER}), nil, nil)
	return e, &r, err
}

// clientHTTP : TLS 1.2 minimum, certificat du serveur vérifié par le magasin du système, proxy d'entreprise respecté.
func clientHTTP(delai time.Duration) *http.Client {
	return &http.Client{Timeout: delai, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}}
}

// ----------------------------------------------------------------------------- client signé

// Client : session authentifiée d'un agent relié.
type Client struct {
	etat *etat.Etat
	cle  *ecdsa.PrivateKey
	http *http.Client
	base string
}

// NouveauClient charge la clé de l'agent (déchiffrée en mémoire par DPAPI sous Windows : elle n'existe
// jamais en clair sur disque) et prépare les requêtes signées vers le serveur.
func NouveauClient(e *etat.Etat, d *etat.Dossier) (*Client, error) {
	clePEM, err := d.LireCle()
	if err != nil {
		return nil, fmt.Errorf("identité de l'agent illisible : %w", err)
	}
	b, _ := pem.Decode(clePEM)
	if b == nil {
		return nil, errors.New("identité de l'agent illisible : clé absente")
	}
	cle, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil || cle.Curve != elliptic.P256() {
		return nil, errors.New("clé de l'agent inattendue (ECDSA P-256 attendue)")
	}
	return &Client{etat: e, cle: cle, base: strings.TrimRight(e.Serveur, "/"), http: clientHTTP(120 * time.Second)}, nil
}

// requete envoie une requête signée et décode la réponse JSON dans `sortie`.
func (c *Client) requete(methode, chemin, requete string, corps []byte, sortie any) error {
	h, err := entetesSignes(c.cle, methode, chemin, corps)
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
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("serveur CACyber injoignable (%s) : %w", c.base, err)
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
	// Annuaire : résumé « façon BloodHound » calculé PAR LE SERVEUR (absent sans données AD).
	Annuaire *ResumeAnnuaire `json:"annuaire,omitempty"`
}

// EtapeChemin : maillon d'un chemin de contrôle (« de —relation→ vers »), en noms lisibles.
type EtapeChemin struct {
	De       string `json:"de"`
	Relation string `json:"relation"`
	Vers     string `json:"vers"`
}

// CheminAD : chemin de contrôle menant à un compte ou groupe privilégié (exposition à réduire).
type CheminAD struct {
	Depuis string        `json:"depuis"`
	Vers   string        `json:"vers"`
	Etapes []EtapeChemin `json:"etapes"`
}

// ResumeAnnuaire : synthèse défensive de l'annuaire Active Directory renvoyée par le serveur.
type ResumeAnnuaire struct {
	Domaine                 string     `json:"domaine"`
	ComptesActifs           int        `json:"comptes_actifs"`
	ComptesPrivilegies      int        `json:"comptes_privilegies"`
	Chemins                 []CheminAD `json:"chemins"`
	ComptesAvecChemin       int        `json:"comptes_avec_chemin"`
	GroupesLargesExposes    []string   `json:"groupes_larges_exposes"`
	Kerberoastables         int        `json:"kerberoastables"`
	ASREP                   int        `json:"asrep"`
	DelegationNonContrainte int        `json:"delegation_non_contrainte"`
	ComptesInactifs         int        `json:"comptes_inactifs"`
	KrbtgtAgeJours          *int       `json:"krbtgt_age_jours"`
	LAPS                    *struct {
		Couverts int `json:"couverts"`
		Total    int `json:"total"`
	} `json:"laps_couverture"`
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

package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"
)

// Serveur HTTPS local (certificat de test httptest : autorité inconnue du système).
func TestControleWebHTTPSSansEntetes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49")
		w.Header().Set("X-Powered-By", "PHP/7.2.0")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 5.1"></head></html>`))
	}))
	defer srv.Close()
	host, port := hotePort(t, srv.Listener.Addr())
	c := ControlerService(context.Background(), host, "", port)
	if c == nil || !c.HTTPS {
		t.Fatalf("service HTTPS non détecté : %+v", c)
	}
	if c.Certificat == nil || !c.Certificat.NonApprouve {
		t.Errorf("certificat de test devrait être non approuvé : %+v", c.Certificat)
	}
	if c.HSTS == nil || *c.HSTS {
		t.Error("HSTS absent non relevé")
	}
	for _, e := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		if !slices.Contains(c.EntetesManquants, e) {
			t.Errorf("en-tête manquant non relevé : %s (%v)", e, c.EntetesManquants)
		}
	}
	for _, x := range []string{"Apache/2.4.49", "PHP/7.2.0", "WordPress 5.1"} {
		if !slices.Contains(c.Technologies, x) {
			t.Errorf("technologie non relevée : %s (%v)", x, c.Technologies)
		}
	}
}

// Serveur HTTP en clair, bien configuré : rien à signaler sauf l'absence de TLS.
func TestControleWebHTTPConforme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
	}))
	defer srv.Close()
	host, port := hotePort(t, srv.Listener.Addr())
	c := ControlerService(context.Background(), host, "", port)
	if c == nil || c.HTTPS || c.Statut != 200 {
		t.Fatalf("contrôle inattendu : %+v", c)
	}
	if len(c.EntetesManquants) != 0 || c.HSTS != nil {
		t.Errorf("faux positif : %+v", c)
	}
}

// Certificat expiré, auto-signé, au nom d'un autre équipement.
func TestAnalyseCertificat(t *testing.T) {
	cle, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	modele := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "autre.exemple"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		DNSNames: []string{"autre.exemple"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, modele, modele, &cle.PublicKey, cle)
	cert, _ := x509.ParseCertificate(der)
	r := analyserCertificat(cert, nil, "10.0.0.5", "nas.local", time.Now())
	if !r.Expire || !r.AutoSigne || !r.NomIncorrect || !r.NonApprouve || r.JoursRestants >= 0 {
		t.Fatalf("analyse incorrecte : %+v", r)
	}
}

// Suites faibles : un serveur qui n'accepte que des suites modernes ne déclenche rien.
func TestSuitesModernesSeulement(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}
	srv.StartTLS()
	defer srv.Close()
	if f := chiffrementsFaibles(context.Background(), srv.Listener.Addr().String()); len(f) != 0 {
		t.Fatalf("suites faibles signalées à tort : %v", f)
	}
}

// Un port qui ne parle ni TLS ni HTTP n'est pas un service web.
func TestPortNonWeb(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	defer l.Close()
	host, port := hotePort(t, l.Addr())
	if c := ControlerService(context.Background(), host, "", port); c != nil {
		t.Fatalf("service non web traité comme web : %+v", c)
	}
}

func hotePort(t *testing.T, a net.Addr) (string, int) {
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

// Requêtes osquery : SELECT uniquement.
func TestRequetesOsqueryLectureSeule(t *testing.T) {
	for nom, q := range RequetesOsquery {
		if err := RequeteLectureSeule(q); err != nil {
			t.Errorf("%s : %v", nom, err)
		}
	}
	for _, q := range []string{"select 1; delete from x", "insert into t values(1)", "attach '/tmp/x' as y", "pragma x"} {
		if RequeteLectureSeule(q) == nil {
			t.Errorf("requête dangereuse acceptée : %s", q)
		}
	}
	o, err := AnalyserOsquery(map[string][]map[string]string{
		"version":   {{"version": "5.24.1"}},
		"bitlocker": {{"drive_letter": "C:", "protection_status": "0"}},
		"securite":  {{"firewall": "Poor", "autoupdate": "Good", "antivirus": "Good", "user_account_control": "Good"}},
	})
	if err != nil || o.Version != "5.24.1" || len(o.BitLocker) != 1 || o.BitLocker[0].Protection || o.PareFeu != "Poor" {
		t.Fatalf("analyse osquery incorrecte : %+v %v", o, err)
	}
}

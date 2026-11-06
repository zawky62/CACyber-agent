package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// Vecteurs du format attendu par le serveur (supabase/functions/_shared/signature_agent.ts) : le
// message signé par l'agent doit être identique octet pour octet.
func TestMessageASignerCompatibleServeur(t *testing.T) {
	cas := []struct {
		methode, chemin, horo, nonce string
		corps                 []byte
		attendu               string
	}{
		{"post", "/agent/v1/scans", "1767225600", "n0nce-unique-0123456789", nil,
			"POST\n/agent/v1/scans\n1767225600\nn0nce-unique-0123456789\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"POST", "/agent/v1/scans/abc/evenements", "1767225600", "AbC_dEf-0123456789xyz", []byte(`{"evenements":[]}`),
			"POST\n/agent/v1/scans/abc/evenements\n1767225600\nAbC_dEf-0123456789xyz\nc3ab6756647a8b2cbc918d9f849aaf4d7a50ded7e379957910211e57c9368200"},
	}
	for _, c := range cas {
		if got := string(MessageASigner(c.methode, c.chemin, c.horo, c.nonce, c.corps)); got != c.attendu {
			t.Errorf("message signé incorrect :\n%q\nattendu\n%q", got, c.attendu)
		}
	}
}

// La signature produite doit se vérifier comme le fait le serveur (ECDSA P-256 / SHA-256, DER).
func TestSignatureVerifiable(t *testing.T) {
	cle, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := MessageASigner("GET", "/agent/v1/moi", "1", NouveauNonce(), nil)
	sig, err := Signer(cle, msg)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(sig)
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(&cle.PublicKey, h[:], der) {
		t.Fatal("signature invérifiable")
	}
}

// Le nonce est unique et respecte le format accepté par le serveur ([A-Za-z0-9_-]{16,64}).
func TestNonceUniqueEtConforme(t *testing.T) {
	vus := map[string]bool{}
	for i := 0; i < 1000; i++ {
		n := NouveauNonce()
		if len(n) < 16 || len(n) > 64 || strings.Trim(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != "" {
			t.Fatalf("nonce non conforme : %q", n)
		}
		if vus[n] {
			t.Fatal("nonce répété")
		}
		vus[n] = true
	}
}

// Le HTTP en clair n'est admis que vers ce poste (ou en mode --dev).
func TestHTTPRefuseHorsPoste(t *testing.T) {
	if _, err := VerifierURLServeur("http://plateforme.exemple.fr", false); err == nil {
		t.Fatal("HTTP en clair vers un hôte distant aurait dû être refusé")
	}
	for _, ok := range []string{"http://localhost:8000", "http://127.0.0.1:8100", "https://plateforme.exemple.fr"} {
		if _, err := VerifierURLServeur(ok, false); err != nil {
			t.Errorf("%s refusé à tort : %v", ok, err)
		}
	}
	u, _ := url.Parse("http://10.0.0.5")
	if EstLocal(u) {
		t.Fatal("10.0.0.5 n'est pas ce poste")
	}
}

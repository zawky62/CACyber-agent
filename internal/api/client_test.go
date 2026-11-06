package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
)

// Vecteurs calculés avec le serveur (backend/app/pki.py:message_a_signer) : le format signé
// par l'agent doit être identique octet pour octet.
func TestMessageASignerCompatibleServeur(t *testing.T) {
	cas := []struct {
		methode, chemin, horo string
		corps                 []byte
		attendu               string
	}{
		{"post", "/agent/v1/scans", "1767225600", nil,
			"POST\n/agent/v1/scans\n1767225600\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"POST", "/agent/v1/scans/abc/evenements", "1767225600", []byte(`{"evenements":[]}`),
			"POST\n/agent/v1/scans/abc/evenements\n1767225600\nc3ab6756647a8b2cbc918d9f849aaf4d7a50ded7e379957910211e57c9368200"},
	}
	for _, c := range cas {
		if got := string(MessageASigner(c.methode, c.chemin, c.horo, c.corps)); got != c.attendu {
			t.Errorf("message signé incorrect :\n%q\nattendu\n%q", got, c.attendu)
		}
	}
}

// La signature produite doit se vérifier comme le fait le serveur (ECDSA P-256 / SHA-256, DER).
func TestSignatureVerifiable(t *testing.T) {
	cle, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	msg := MessageASigner("GET", "/agent/v1/moi", "1", nil)
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

package outils

import (
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Lecture, en Go pur, de l'identité du SIGNATAIRE Authenticode d'un exécutable PE.
//
// La VALIDITÉ cryptographique de la signature (empreinte du fichier, chaîne jusqu'à une racine de
// confiance) est contrôlée par Windows (WinVerifyTrust, signature_windows.go). Ce fichier répond à
// l'autre question : QUI a signé ? On lit la table des certificats du PE (PKCS#7 SignedData), on
// prend le PREMIER SignerInfo et on retrouve SON certificat par émetteur + numéro de série. Ne pas
// se contenter de « un certificat du lot porte le bon nom » : un attaquant pourrait joindre le
// certificat de l'éditeur à une signature faite avec sa propre clé.

type contenuPKCS7 struct {
	Type    asn1.ObjectIdentifier
	Contenu asn1.RawValue `asn1:"explicit,tag:0"`
}

type donneesSignees struct {
	Version     int
	Algorithmes asn1.RawValue
	Encapsule   asn1.RawValue
	Certificats asn1.RawValue `asn1:"optional,tag:0"`
	Revocations asn1.RawValue `asn1:"optional,tag:1"`
	Signataires asn1.RawValue
}

type emetteurEtSerie struct {
	Emetteur asn1.RawValue
	Serie    *big.Int
}

type infoSignataire struct {
	Version int
	ID      emetteurEtSerie
}

var oidDonneesSignees = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// pkcs7DuPE extrait le bloc PKCS#7 de la table des certificats (répertoire de sécurité) d'un PE.
func pkcs7DuPE(r io.ReaderAt) ([]byte, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("exécutable PE illisible : %w", err)
	}
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	}
	if dir.Size < 8 || dir.Size > 1<<20 {
		return nil, errors.New("aucune signature Authenticode intégrée")
	}
	// Pour ce répertoire, VirtualAddress est un DÉCALAGE DANS LE FICHIER (pas une adresse virtuelle).
	brut := make([]byte, dir.Size)
	if _, err := r.ReadAt(brut, int64(dir.VirtualAddress)); err != nil {
		return nil, fmt.Errorf("table des certificats illisible : %w", err)
	}
	// WIN_CERTIFICATE : dwLength (4), wRevision (2), wCertificateType (2), bCertificate…
	long := binary.LittleEndian.Uint32(brut[0:4])
	typ := binary.LittleEndian.Uint16(brut[6:8])
	if typ != 0x0002 || long < 8 || long > dir.Size { // WIN_CERT_TYPE_PKCS_SIGNED_DATA
		return nil, errors.New("signature Authenticode de type inattendu")
	}
	return brut[8:long], nil
}

// SignataireDuPKCS7 renvoie le certificat du premier signataire d'un SignedData DER.
func SignataireDuPKCS7(der []byte) (*x509.Certificate, error) {
	var ci contenuPKCS7
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("PKCS#7 illisible : %w", err)
	}
	if !ci.Type.Equal(oidDonneesSignees) {
		return nil, errors.New("PKCS#7 : SignedData attendu")
	}
	var sd donneesSignees
	if _, err := asn1.Unmarshal(ci.Contenu.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData illisible : %w", err)
	}
	certs, err := x509.ParseCertificates(sd.Certificats.Bytes)
	if err != nil || len(certs) == 0 {
		return nil, errors.New("SignedData sans certificat lisible")
	}
	// Premier SignerInfo du SET.
	var premier asn1.RawValue
	if _, err := asn1.Unmarshal(sd.Signataires.Bytes, &premier); err != nil {
		return nil, fmt.Errorf("SignerInfo illisible : %w", err)
	}
	var si infoSignataire
	if _, err := asn1.Unmarshal(premier.FullBytes, &si); err != nil {
		return nil, fmt.Errorf("SignerInfo illisible : %w", err)
	}
	if si.ID.Serie == nil {
		return nil, errors.New("SignerInfo sans émetteur ni numéro de série")
	}
	for _, c := range certs {
		if c.SerialNumber.Cmp(si.ID.Serie) == 0 && bytes.Equal(c.RawIssuer, si.ID.Emetteur.FullBytes) {
			return c, nil
		}
	}
	return nil, errors.New("certificat du signataire absent de la signature")
}

// OrganisationSignataire renvoie l'organisation (O=) du signataire Authenticode d'un PE.
func OrganisationSignataire(r io.ReaderAt) (string, error) {
	der, err := pkcs7DuPE(r)
	if err != nil {
		return "", err
	}
	c, err := SignataireDuPKCS7(der)
	if err != nil {
		return "", err
	}
	if len(c.Subject.Organization) == 0 {
		return "", errors.New("certificat du signataire sans organisation")
	}
	return c.Subject.Organization[0], nil
}

// signataireAdmis : l'organisation figure-t-elle dans la liste du manifeste ?
func signataireAdmis(org string, admis []string) bool {
	for _, a := range admis {
		if org == a {
			return true
		}
	}
	return false
}

//go:build windows

package annuaire

import (
	"github.com/go-ldap/ldap/v3/gssapi"

	"cacyber/agent/internal/identifiants"
)

// lier authentifie la session par SSPI (Kerberos, repli NTLM) — le mot de passe ne circule jamais :
//   - sans identifiants : identité Windows du compte de domaine qui exécute l'agent, avec liaison au
//     canal TLS (« channel binding ») quand le certificat du contrôleur est disponible ;
//   - avec identifiants fournis par l'entité : jeton SSPI construit à partir de ceux-ci, en mémoire.
func lier(s *session, domaine string, id *identifiants.Identifiants) error {
	var client *gssapi.SSPIClient
	var err error
	if id.Present() {
		err = id.Avec(func(mdp string) error {
			dom := id.Domaine
			if dom == "" {
				dom = domaine
			}
			client, err = gssapi.NewSSPIClientWithUserCredentials(dom, id.Utilisateur, mdp)
			return err
		})
	} else if etat, ok := s.c.TLSConnectionState(); ok && len(etat.PeerCertificates) > 0 {
		client, err = gssapi.NewSSPIClientWithChannelBinding(etat.PeerCertificates[0])
	} else {
		client, err = gssapi.NewSSPIClient()
	}
	if err != nil {
		return err
	}
	defer client.Close()
	return s.c.GSSAPIBind(client, "ldap/"+s.hote, "")
}

// Package identifiants conserve les identifiants fournis par l'entité contrôlée (compte de domaine
// pour l'annuaire, compte d'administration pour l'inventaire authentifié WinRM / SSH).
//
// Règles NON NÉGOCIABLES :
//   - saisis localement, sur le poste, par l'entité elle-même ;
//   - gardés EN MÉMOIRE uniquement : jamais écrits sur disque, jamais transmis au serveur CACyber,
//     jamais journalisés (affichage masqué, sérialisation JSON / texte refusée) ;
//   - effacés (mise à zéro) dès la fin de la collecte.
package identifiants

import (
	"errors"
	"strings"
	"sync"
)

// Identifiants : compte et mot de passe (le mot de passe est un tableau d'octets effaçable).
type Identifiants struct {
	mu          sync.Mutex
	Domaine     string
	Utilisateur string
	motDePasse  []byte
}

// Nouveaux crée des identifiants ; `motDePasse` est COPIÉ puis l'original est effacé.
func Nouveaux(domaine, utilisateur string, motDePasse []byte) *Identifiants {
	i := &Identifiants{Domaine: strings.TrimSpace(domaine), Utilisateur: strings.TrimSpace(utilisateur),
		motDePasse: append([]byte(nil), motDePasse...)}
	Effacer(motDePasse)
	// « DOMAINE\utilisateur » ou « utilisateur@domaine » : domaine déduit si non fourni.
	if i.Domaine == "" {
		if d, u, ok := strings.Cut(i.Utilisateur, `\`); ok {
			i.Domaine, i.Utilisateur = d, u
		} else if u, d, ok := strings.Cut(i.Utilisateur, "@"); ok {
			i.Domaine, i.Utilisateur = d, u
		}
	}
	return i
}

// Avec donne un accès TEMPORAIRE au mot de passe (copie effacée après l'appel).
func (i *Identifiants) Avec(f func(motDePasse string) error) error {
	if i == nil {
		return errors.New("identifiants absents")
	}
	i.mu.Lock()
	if i.motDePasse == nil {
		i.mu.Unlock()
		return errors.New("identifiants effacés")
	}
	copie := append([]byte(nil), i.motDePasse...)
	i.mu.Unlock()
	defer Effacer(copie)
	return f(string(copie))
}

// Present indique si un mot de passe est disponible.
func (i *Identifiants) Present() bool {
	if i == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.motDePasse != nil
}

// Effacer met à zéro le mot de passe ; les identifiants deviennent inutilisables.
func (i *Identifiants) Effacer() {
	if i == nil {
		return
	}
	i.mu.Lock()
	Effacer(i.motDePasse)
	i.motDePasse = nil
	i.mu.Unlock()
}

// String : jamais le mot de passe (affichage et journaux).
func (i *Identifiants) String() string {
	if i == nil {
		return "<aucun>"
	}
	if i.Domaine != "" {
		return i.Domaine + `\` + i.Utilisateur + " (mot de passe masqué)"
	}
	return i.Utilisateur + " (mot de passe masqué)"
}

// GoString : même masquage pour le format %#v.
func (i *Identifiants) GoString() string { return i.String() }

// ErrSerialisation : les identifiants ne doivent jamais être sérialisés (fichier, réseau, journal).
var ErrSerialisation = errors.New("identifiants : sérialisation interdite")

// MarshalJSON refuse toute sérialisation JSON.
func (i *Identifiants) MarshalJSON() ([]byte, error) { return nil, ErrSerialisation }

// MarshalText refuse toute sérialisation texte.
func (i *Identifiants) MarshalText() ([]byte, error) { return nil, ErrSerialisation }

// Effacer met un tableau d'octets à zéro.
func Effacer(b []byte) {
	for k := range b {
		b[k] = 0
	}
}

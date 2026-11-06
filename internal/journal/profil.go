package journal

import (
	"fmt"

	"cacyber/agent/internal/scan"
)

// DefinirProfil retient le profil de scan choisi sur le poste (écran « Scan » de l'interface).
//
// Seul un NOM de profil compilé dans l'agent est accepté (decouverte, standard, approfondi,
// industriel) : jamais une option Nmap. Tous les profils restent en lecture seule, en mode connect,
// bornés aux plages autorisées par le mandat. Une chaîne vide rétablit le profil du serveur.
func (m *Mission) DefinirProfil(nom string) error {
	if nom != "" {
		if _, connu := scan.ProfilDepuis(nom); !connu {
			return fmt.Errorf("profil de scan inconnu : %q", nom)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.occupe {
		return fmt.Errorf("un scan est en cours : le profil ne peut plus être modifié")
	}
	m.profilLocal = nom
	return nil
}

// ProfilLocal renvoie le profil choisi sur le poste ("" = profil du serveur).
func (m *Mission) ProfilLocal() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.profilLocal
}

// profilEffectif : le choix du poste prime sur la proposition du serveur ; il est consigné au journal.
func (m *Mission) profilEffectif(serveur string) string {
	m.mu.Lock()
	local := m.profilLocal
	m.mu.Unlock()
	if local == "" {
		return serveur
	}
	if local != serveur {
		m.log(1, "info", fmt.Sprintf("Profil de scan choisi sur le poste : %s (proposé par le cabinet : %s).",
			local, valeurOu(serveur, "standard")), -1)
	}
	return local
}

// Package authinv réalise l'inventaire AUTHENTIFIÉ des postes et serveurs (brief §15.3, mode 2) avec
// les identifiants fournis par l'entité pour son propre réseau : WinRM (Windows) et SSH (Linux).
//
// Garde-fous :
//   - uniquement des hôtes situés DANS les plages autorisées par le mandat (contrôle avant connexion) ;
//   - commandes de LECTURE figées dans le code (liste blanche testée) : aucune commande issue d'une
//     saisie ou du serveur, aucune écriture, aucune installation, aucun service démarré ;
//   - identifiants en mémoire seulement (paquet identifiants), jamais journalisés ni transmis ;
//   - délai borné par hôte, quatre hôtes au plus en parallèle, 256 hôtes au plus par collecte.
package authinv

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"cacyber/agent/internal/identifiants"
	"cacyber/agent/internal/scan"
)

// Options : paramètres de l'inventaire authentifié.
type Options struct {
	Windows *identifiants.Identifiants // compte d'administration Windows (WinRM)
	Linux   *identifiants.Identifiants // compte SSH
	// WinRMHTTP autorise le port 5985 (HTTP, authentification NTLM sans transmission du mot de passe)
	// quand HTTPS (5986) est indisponible. Désactivé par défaut.
	WinRMHTTP bool
	// WinRMCertificatNonVerifie : accepte un certificat WinRM non vérifiable (autosigné). Désactivé par
	// défaut : un intermédiaire pourrait relayer l'authentification.
	WinRMCertificatNonVerifie bool
	// SSHHotesConnus : fichier known_hosts de l'entité ; toute clé d'hôte inconnue ou différente est refusée.
	// OBLIGATOIRE pour l'inventaire SSH, sauf acceptation explicite ci-dessous.
	SSHHotesConnus string
	// SSHClesNonVerifiees : accepte une clé d'hôte SSH non vérifiée (relevée et journalisée). Désactivé par
	// défaut : sans vérification, un intermédiaire usurpant l'hôte capterait le mot de passe saisi.
	SSHClesNonVerifiees bool
	Delai          time.Duration // par hôte (défaut 90 s)
	Journal        func(string)
}

// MaxHotesAuth : nombre maximal d'hôtes inventoriés par collecte.
const MaxHotesAuth = 256

// DansPerimetre : l'adresse appartient-elle à l'une des plages autorisées ?
func DansPerimetre(ip string, reseaux []string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, r := range reseaux {
		if p, err := netip.ParsePrefix(r); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// Inventorier interroge les hôtes découverts qui exposent WinRM (5985/5986) ou SSH (22) et fusionne les
// résultats dans les observations (système, logiciels, correctifs, administrateurs locaux).
func Inventorier(ctx context.Context, obs *scan.Observations, o Options) []scan.InventaireAuthHote {
	if o.Journal == nil {
		o.Journal = func(string) {}
	}
	if o.Delai <= 0 {
		o.Delai = 90 * time.Second
	}
	type tache struct {
		i       int
		methode string
	}
	var taches []tache
	for i, h := range obs.Hotes {
		if !DansPerimetre(h.IP, obs.Reseaux) {
			continue // hors mandat : jamais de connexion
		}
		ports := map[int]bool{}
		for _, p := range h.Ports {
			ports[p.Port] = true
		}
		switch {
		case o.Windows.Present() && (ports[5986] || (o.WinRMHTTP && ports[5985])):
			taches = append(taches, tache{i, "winrm"})
		case o.Linux.Present() && ports[22]:
			taches = append(taches, tache{i, "ssh"})
		}
		if len(taches) >= MaxHotesAuth {
			break
		}
	}
	if len(taches) == 0 {
		return nil
	}
	o.Journal(fmt.Sprintf("Inventaire authentifié : %d hôte(s) du périmètre autorisé, commandes de lecture seule.", len(taches)))
	res := make([]scan.InventaireAuthHote, len(taches))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for k, t := range taches {
		wg.Add(1)
		sem <- struct{}{}
		go func(k int, t tache) {
			defer wg.Done()
			defer func() { <-sem }()
			hctx, annuler := context.WithTimeout(ctx, o.Delai)
			defer annuler()
			h := obs.Hotes[t.i]
			var r resultat
			var err error
			if t.methode == "winrm" {
				r, err = inventaireWinRM(hctx, h.IP, h.Ports, o)
			} else {
				r, err = inventaireSSH(hctx, h.IP, o)
			}
			bilan := scan.InventaireAuthHote{IP: h.IP, Methode: t.methode, OK: err == nil}
			if err != nil {
				bilan.Erreur = nettoyer(err.Error())
			} else {
				bilan = r.bilan(bilan)
				mu.Lock()
				fusionner(&obs.Hotes[t.i], r)
				mu.Unlock()
			}
			res[k] = bilan
		}(k, t)
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool { return res[i].IP < res[j].IP })
	ok := 0
	for _, r := range res {
		if r.OK {
			ok++
		}
	}
	o.Journal(fmt.Sprintf("Inventaire authentifié : %d/%d hôte(s) inventorié(s).", ok, len(res)))
	return res
}

// resultat : données lues sur un hôte.
type resultat struct {
	os          *scan.SystemeExploitation
	logiciels   []scan.Logiciel
	correctifs  []scan.Correctif
	admins      []string
	antivirus   *scan.Antivirus
	pareFeu     *bool
	chiffrement *bool
	racineSSH   *bool
	mdpSSH      *bool
	empreinte   string
}

func (r resultat) bilan(b scan.InventaireAuthHote) scan.InventaireAuthHote {
	b.Logiciels, b.Correctifs = len(r.logiciels), len(r.correctifs)
	b.PareFeuActif, b.ChiffrementDisque, b.SSHRacineAutorisee, b.SSHMotDePasse = r.pareFeu, r.chiffrement, r.racineSSH, r.mdpSSH
	b.EmpreinteCleHote = r.empreinte
	return b
}

// fusionner rattache les données à l'hôte, sans écraser un inventaire local déjà présent.
func fusionner(h *scan.Hote, r resultat) {
	if r.os != nil && r.os.Nom != "" {
		h.OS = r.os
	}
	if h.Inventaire == nil {
		h.Inventaire = &scan.Inventaire{}
	}
	inv := h.Inventaire
	if len(inv.Logiciels) == 0 {
		inv.Logiciels = r.logiciels
	}
	if len(inv.Correctifs) == 0 {
		inv.Correctifs = r.correctifs
	}
	if inv.Antivirus == nil {
		inv.Antivirus = r.antivirus
	}
	if len(inv.Comptes) == 0 {
		for _, a := range r.admins {
			inv.Comptes = append(inv.Comptes, scan.Compte{Nom: a, Actif: true, Admin: true})
		}
	}
}

// nettoyer : message d'erreur court, sans aucune donnée d'authentification.
func nettoyer(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

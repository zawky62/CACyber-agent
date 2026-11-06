package scan

import (
	"fmt"
	"net"
	"net/netip"
)

// Cibles : réseaux retenus et adresses à examiner.
type Cibles struct {
	Reseaux []string     // notation CIDR, pour les observations et le journal
	Hotes   []netip.Addr // adresses individuelles (bornées par MaxHotes de la politique)
	Tronque bool         // vrai si la limite d'hôtes a été atteinte
}

// estPrive : seules les plages internes (RFC 1918, boucle locale) sont admissibles.
// L'agent n'examine JAMAIS d'adresse publique, quel que soit le contenu de la politique.
func estPrive(a netip.Addr) bool {
	return a.Is4() && (a.IsPrivate() || a.IsLoopback())
}

// CalculerCibles détermine les adresses à examiner :
//   - si le mandat précise des plages (politique.plages_autorisees), uniquement celles-ci ;
//   - sinon, les sous-réseaux IPv4 privés directement connectés au poste, chacun ramené
//     au /24 qui entoure l'adresse de l'agent.
//
// maxHotes borne le nombre total d'adresses (politique.max_hotes).
func CalculerCibles(plages []string, interfaces []netip.Prefix, maxHotes int) (Cibles, error) {
	if maxHotes <= 0 || maxHotes > MaxHotes {
		maxHotes = 1024
	}
	var prefixes []netip.Prefix
	if len(plages) > 0 {
		for _, p := range plages {
			pr, err := netip.ParsePrefix(p)
			if err != nil {
				return Cibles{}, fmt.Errorf("plage invalide %q : %w", p, err)
			}
			pr = pr.Masked()
			if !estPrive(pr.Addr()) || pr.Bits() < 16 {
				return Cibles{}, fmt.Errorf("plage refusée %q : seules les plages privées de /16 à /32 sont admises", p)
			}
			prefixes = append(prefixes, pr)
		}
	} else {
		for _, itf := range interfaces {
			a := itf.Addr()
			if !estPrive(a) || a.IsLoopback() {
				continue
			}
			bits := itf.Bits()
			if bits < 24 {
				bits = 24 // on ne balaie que le /24 qui entoure l'adresse du poste
			}
			prefixes = append(prefixes, netip.PrefixFrom(a, bits).Masked())
		}
	}
	var c Cibles
	vus := map[netip.Addr]bool{}
	for _, pr := range prefixes {
		c.Reseaux = append(c.Reseaux, pr.String())
		for a := pr.Addr(); pr.Contains(a); a = a.Next() {
			// Adresse de réseau et de diffusion ignorées, sauf pour les très petits préfixes.
			if pr.Bits() <= 30 && (a == pr.Addr() || !pr.Contains(a.Next())) {
				continue
			}
			if vus[a] {
				continue
			}
			if len(c.Hotes) >= maxHotes {
				c.Tronque = true
				return c, nil
			}
			vus[a] = true
			c.Hotes = append(c.Hotes, a)
		}
	}
	return c, nil
}

// InterfacesLocales renvoie les préfixes IPv4 des interfaces actives du poste.
func InterfacesLocales() []netip.Prefix {
	var res []netip.Prefix
	itfs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, itf := range itfs {
		if itf.Flags&net.FlagUp == 0 || itf.Flags&net.FlagLoopback != 0 {
			continue
		}
		adrs, _ := itf.Addrs()
		for _, ad := range adrs {
			if ipn, ok := ad.(*net.IPNet); ok {
				if a, ok := netip.AddrFromSlice(ipn.IP.To4()); ok && ipn.IP.To4() != nil {
					uns, _ := ipn.Mask.Size()
					res = append(res, netip.PrefixFrom(a, uns))
				}
			}
		}
	}
	return res
}

// AdressesLocales : adresses IPv4 du poste (pour rattacher l'inventaire au bon hôte).
func AdressesLocales() map[string]bool {
	res := map[string]bool{"127.0.0.1": true}
	for _, p := range InterfacesLocales() {
		res[p.Addr().String()] = true
	}
	return res
}

package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scanner natif, utilisé quand Nmap n'est pas disponible. Il se limite à :
//   - des connexions TCP complètes (« connect ») sur la liste de ports de la politique ;
//   - la LECTURE des bannières que les services envoient spontanément (SSH, FTP) ;
//   - une requête HTTP GET « / » sans identifiants, pour lire si une authentification est exigée ;
//   - des poignées de main TLS, une par version, pour connaître les versions acceptées.
// Aucune donnée n'est envoyée au-delà de ces échanges standard : pas d'identifiant, pas de charge.

const (
	delaiConnexion = 800 * time.Millisecond
	delaiLecture   = 2 * time.Second
	concurrenceMax = 64
)

// nomsServices : libellés usuels des ports (affichage et classement côté serveur).
var nomsServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 53: "domain", 80: "http", 88: "kerberos", 102: "iso-tsap", 135: "msrpc",
	139: "netbios-ssn", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 502: "modbus", 515: "printer",
	1433: "ms-sql-s", 3306: "mysql", 3389: "ms-wbt-server", 5000: "http", 5001: "https", 5900: "vnc",
	8080: "http-proxy", 8443: "https-alt", 9100: "jetdirect", 47808: "bacnet",
}

// Progression : rappel optionnel (hôtes traités, total) pour l'interface.
type Progression func(fait, total int)

// ScannerNatif examine les hôtes et renvoie ceux qui ont au moins un port ouvert.
func ScannerNatif(ctx context.Context, hotes []netip.Addr, ports []int, prog Progression) []Hote {
	return ScannerNatifProfil(ctx, hotes, ports, concurrenceMax, prog)
}

// ConcurrenceNative : connexions simultanées du scanner natif pour un profil (le profil industriel
// n'ouvre qu'une connexion à la fois, comme --max-parallelism 1 pour Nmap).
func (p ParametresProfil) ConcurrenceNative() int {
	if p.MaxParallelisme > 0 {
		return p.MaxParallelisme
	}
	return concurrenceMax
}

// ScannerNatifProfil : idem, avec un nombre maximal de connexions simultanées.
func ScannerNatifProfil(ctx context.Context, hotes []netip.Addr, ports []int, concurrence int, prog Progression) []Hote {
	if concurrence < 1 || concurrence > concurrenceMax {
		concurrence = concurrenceMax
	}
	type cle struct {
		ip   netip.Addr
		port int
	}
	var (
		mu      sync.Mutex
		ouverts = map[netip.Addr][]int{}
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrence)
	)
	travaux := make(chan cle)
	go func() {
		defer close(travaux)
		for _, h := range hotes {
			for _, p := range ports {
				select {
				case travaux <- cle{h, p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	total, fait := len(hotes)*len(ports), 0
	for t := range travaux {
		sem <- struct{}{}
		wg.Add(1)
		go func(t cle) {
			defer func() { <-sem; wg.Done() }()
			d := net.Dialer{Timeout: delaiConnexion}
			conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(t.ip, uint16(t.port)).String())
			mu.Lock()
			defer mu.Unlock()
			fait++
			if prog != nil && len(ports) > 0 && fait%len(ports) == 0 {
				prog(fait/len(ports), total/len(ports))
			}
			if err != nil {
				return
			}
			_ = conn.Close()
			ouverts[t.ip] = append(ouverts[t.ip], t.port)
		}(t)
	}
	wg.Wait()

	// Approfondissement (lecture seule) des seuls hôtes répondants.
	var res []Hote
	for ip, ps := range ouverts {
		sort.Ints(ps)
		h := Hote{IP: ip.String(), Nom: nomInverse(ip)}
		for _, p := range ps {
			h.Ports = append(h.Ports, decrirePort(ctx, ip, p))
		}
		res = append(res, h)
	}
	sort.Slice(res, func(i, j int) bool {
		a, _ := netip.ParseAddr(res[i].IP)
		b, _ := netip.ParseAddr(res[j].IP)
		return a.Less(b)
	})
	return res
}

// nomInverse : nom DNS de l'hôte (résolution inverse), sans le suffixe de domaine.
func nomInverse(ip netip.Addr) string {
	ctx, annuler := context.WithTimeout(context.Background(), time.Second)
	defer annuler()
	noms, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(noms) == 0 {
		return ""
	}
	n := strings.TrimSuffix(noms[0], ".")
	if i := strings.IndexByte(n, '.'); i > 0 {
		n = n[:i]
	}
	return strings.ToUpper(n)
}

var (
	rxSSH = regexp.MustCompile(`^SSH-[\d.]+-([A-Za-z]+)[_-]([\w.]+)`)
	rxFTP = regexp.MustCompile(`(?i)^220[- ].*?\b(vsftpd|proftpd|pure-ftpd|filezilla server|microsoft ftp service)\b[ (v]*([\d.]+[a-z0-9]*)?`)
)

// decrirePort complète un port ouvert avec ce que le service annonce de lui-même.
func decrirePort(ctx context.Context, ip netip.Addr, port int) Port {
	p := Port{Port: port, Proto: "tcp", Service: nomsServices[port]}
	adr := netip.AddrPortFrom(ip, uint16(port)).String()
	switch port {
	case 22, 21:
		if l := lireBanniere(adr); l != "" {
			if m := rxSSH.FindStringSubmatch(l); m != nil {
				p.Produit, p.Version = m[1], m[2]
			} else if m := rxFTP.FindStringSubmatch(l); m != nil {
				p.Produit, p.Version = m[1], m[2]
			}
		}
	case 80, 8080:
		if v, ok := authHTTP(ctx, "http://"+adr+"/"); ok {
			p.HTTPAuthRequise = &v
		}
	case 443, 8443, 5001:
		p.TLS = versionsTLS(adr)
	}
	return p
}

// Completer ajoute, après un passage de Nmap, les relevés natifs non intrusifs que les scripts
// « safe » ne fournissent pas toujours : versions TLS acceptées et exigence d'authentification HTTP.
func Completer(ctx context.Context, h *Hote) {
	ip, err := netip.ParseAddr(h.IP)
	if err != nil {
		return
	}
	for i := range h.Ports {
		p := &h.Ports[i]
		adr := netip.AddrPortFrom(ip, uint16(p.Port)).String()
		switch p.Port {
		case 80, 8080:
			if p.HTTPAuthRequise == nil {
				if v, ok := authHTTP(ctx, "http://"+adr+"/"); ok {
					p.HTTPAuthRequise = &v
				}
			}
		case 443, 8443, 5001:
			if len(p.TLS) == 0 {
				p.TLS = versionsTLS(adr)
			}
		}
	}
}

// lireBanniere lit la première ligne envoyée spontanément par le service (aucune commande envoyée).
func lireBanniere(adr string) string {
	conn, err := net.DialTimeout("tcp", adr, delaiConnexion)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(delaiLecture))
	l, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(l)
}

// authHTTP effectue UN GET sans identifiants et lit si le serveur répond 401 (authentification
// exigée). Aucune tentative d'authentification n'est faite. Le corps de réponse n'est pas lu.
func authHTTP(ctx context.Context, url string) (bool, bool) {
	cli := http.Client{Timeout: delaiLecture, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("User-Agent", "CACyber-Agent (audit en lecture seule)")
	resp, err := cli.Do(req)
	if err != nil {
		return false, false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden, true
}

// versionsTLS teste chaque version de TLS séparément et renvoie celles que le serveur accepte.
func versionsTLS(adr string) []string {
	versions := []struct {
		v   uint16
		nom string
	}{{tls.VersionTLS10, "TLSv1.0"}, {tls.VersionTLS11, "TLSv1.1"}, {tls.VersionTLS12, "TLSv1.2"}, {tls.VersionTLS13, "TLSv1.3"}}
	var acceptees []string
	for _, v := range versions {
		cfg := &tls.Config{
			// InsecureSkipVerify : nous ne faisons QUE lire la version négociée ; aucune donnée
			// n'est échangée après la poignée de main, la vérification du certificat est sans objet ici.
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         v.v,
			MaxVersion:         v.v,
		}
		d := net.Dialer{Timeout: delaiConnexion}
		conn, err := tls.DialWithDialer(&d, "tcp", adr, cfg)
		if err == nil {
			acceptees = append(acceptees, v.nom)
			_ = conn.Close()
		}
	}
	return acceptees
}

// DevinerType : classement indicatif d'un hôte d'après ses ports (le serveur a sa propre logique).
func DevinerType(h *Hote) {
	if h.Type != "" {
		return
	}
	a := map[int]bool{}
	for _, p := range h.Ports {
		a[p.Port] = true
	}
	switch {
	case a[502] || a[102] || a[47808]:
		h.Type = "automate"
	case a[9100] || a[515]:
		h.Type = "imprimante"
	case a[5000] || a[5001]:
		h.Type = "nas"
	case a[88] && a[389]:
		h.Type = "serveur"
	case a[445] || a[135]:
		h.Type = "poste"
	}
}

// Resume : description courte d'un hôte pour le journal (« NOM (ip) : ports 135, 445. »).
func Resume(h Hote) string {
	var ps []string
	for _, p := range h.Ports {
		ps = append(ps, fmt.Sprint(p.Port))
	}
	nom := h.Nom
	if nom == "" {
		nom = h.IP
	}
	if len(ps) == 0 {
		return fmt.Sprintf("%s (%s) : aucun port ouvert parmi ceux contrôlés.", nom, h.IP)
	}
	return fmt.Sprintf("%s (%s) : ports %s.", nom, h.IP, strings.Join(ps, ", "))
}

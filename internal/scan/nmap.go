package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"

	"cacyber/agent/internal/outils"
)

// Intégration de Nmap (https://nmap.org) en SOUS-PROCESSUS.
//
// LICENCE : Nmap est un logiciel libre (Nmap Public Source License, NPSL), gratuit. L'agent ne le
// redistribue pas et ne s'y lie pas : il appelle, en processus séparé, l'installation du poste
// (installateur officiel de nmap.org), dont la signature Authenticode est vérifiée avant CHAQUE
// exécution (paquet outils). Voir docs/NMAP.md.
//
// Garde-fous : options figées dans ce fichier et dans profils.go, scripts limités à la liste blanche
// compilée (catégorie « safe »), jamais d'option --script-args, jamais de catégorie de scripts, jamais
// de scan UDP, de fragmentation, d'usurpation ni de détection d'OS. Mode « connect » non privilégié
// (--unprivileged -sT) : ni Npcap ni droits administrateur, comportement identique sur tout poste.

var rxVersionNmap = regexp.MustCompile(`Nmap version ([\d.]+)`)

// VersionNmap renvoie la version du Nmap vérifié (« 7.95 ») ou une chaîne vide.
func VersionNmap(ctx context.Context, x *outils.Executable) string {
	out, err := x.Commande(ctx, "--version").Output()
	if err != nil {
		return ""
	}
	if m := rxVersionNmap.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// ArgumentsNmap construit la ligne de commande. Toute option vient du code (profil) ; la politique
// du serveur ne fournit qu'un NOM de profil, des ports (entiers validés), un gabarit T2/T3 et des
// noms de scripts filtrés par la liste blanche. Les cibles sont passées par fichier (-iL), jamais
// interprétées.
func ArgumentsNmap(p ParametresProfil, ports []int, scripts []string, timing, fichierCibles string,
	inclureFragiles bool) ([]string, error) {
	for _, s := range scripts {
		if !ListeBlancheNSE[s] {
			return nil, fmt.Errorf("script Nmap refusé (hors liste blanche) : %q", s)
		}
	}
	ps := p.Ports(ports, inclureFragiles)
	if len(ps) == 0 {
		return nil, fmt.Errorf("profil %s : aucun port autorisé à examiner", p.Nom)
	}
	args := []string{"--unprivileged", "-sT"}
	if p.DetectionVersion {
		if p.IntensiteVersion == 2 {
			args = append(args, "-sV", "--version-light")
		} else {
			args = append(args, "-sV", "--version-intensity", strconv.Itoa(p.IntensiteVersion))
		}
	}
	args = append(args, "-"+p.TimingProfil(timing), "--max-retries", strconv.Itoa(p.MaxRetries),
		"--host-timeout", p.HostTimeout)
	if p.ScanDelay != "" {
		args = append(args, "--scan-delay", p.ScanDelay)
	}
	if p.MaxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(p.MaxRate))
	}
	if p.MaxParallelisme > 0 {
		args = append(args, "--max-parallelism", strconv.Itoa(p.MaxParallelisme))
	}
	if len(p.PortsDecouverte) > 0 {
		args = append(args, "-PS"+joindre(p.PortsDecouverte))
	}
	args = append(args, "-p", joindre(ps), "-oX", "-", "-iL", fichierCibles)
	if p.Scripts && len(scripts) > 0 {
		args = append(args, "--script", strings.Join(scripts, ","))
	}
	return args, nil
}

// ExecuterNmap lance le Nmap VÉRIFIÉ sur les hôtes fournis et convertit sa sortie XML en observations.
func ExecuterNmap(ctx context.Context, x *outils.Executable, p ParametresProfil, hotes []netip.Addr, ports []int,
	scripts []string, timing string, inclureFragiles bool) ([]Hote, map[string]any, error) {
	f, err := os.CreateTemp("", "cacyber-cibles-*.txt")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(f.Name())
	for _, h := range hotes {
		fmt.Fprintln(f, h.String())
	}
	_ = f.Close()
	args, err := ArgumentsNmap(p, ports, scripts, timing, f.Name(), inclureFragiles)
	if err != nil {
		return nil, nil, err
	}
	out, err := x.Commande(ctx, args...).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("exécution de Nmap : %w", err)
	}
	res, meta, err := AnalyserXMLNmap(out)
	if err != nil {
		return nil, nil, err
	}
	// Traçabilité (NEP 500) : la commande exacte figure dans les observations, sans le
	// chemin du fichier temporaire.
	argsTrace := append([]string{}, args...)
	for i := range argsTrace {
		if argsTrace[i] == "-iL" && i+1 < len(argsTrace) {
			argsTrace[i+1] = "<cibles>"
		}
	}
	meta["arguments"] = strings.Join(argsTrace, " ")
	meta["scripts"] = scripts
	meta["profil"] = string(p.Nom)
	meta["sha256"] = x.SHA256
	meta["signataire"] = x.Signataire
	return res, meta, nil
}

// ----------------------------------------------------------------------------- XML Nmap

type xmlRun struct {
	Version string    `xml:"version,attr"`
	Hosts   []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports       []xmlPort   `xml:"ports>port"`
	HostScripts []xmlScript `xml:"hostscript>script"`
}

type xmlPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
		OSType  string `xml:"ostype,attr"`
	} `xml:"service"`
	Scripts []xmlScript `xml:"script"`
}

type xmlScript struct {
	ID     string    `xml:"id,attr"`
	Output string    `xml:"output,attr"`
	Elems  []xmlElem `xml:"elem"`
}

type xmlElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func (s xmlScript) elem(cle string) string {
	for _, e := range s.Elems {
		if e.Key == cle {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

var rxDialecte = regexp.MustCompile(`(?m)^\s*(NT LM 0\.12 \(SMBv1\)|[23][:.]\d[:.]\d+)`)

// AnalyserXMLNmap convertit la sortie « -oX » en hôtes (seuls les hôtes « up » avec au moins
// un port ouvert ou une information de script sont retenus).
func AnalyserXMLNmap(data []byte) ([]Hote, map[string]any, error) {
	var run xmlRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, nil, fmt.Errorf("sortie XML de Nmap illisible : %w", err)
	}
	var res []Hote
	for _, xh := range run.Hosts {
		if xh.Status.State != "up" {
			continue
		}
		h := Hote{}
		for _, a := range xh.Addresses {
			switch a.Type {
			case "ipv4":
				h.IP = a.Addr
			case "mac":
				h.Fabricant = a.Vendor
			}
		}
		if h.IP == "" {
			continue
		}
		if len(xh.Hostnames) > 0 {
			n := xh.Hostnames[0].Name
			if i := strings.IndexByte(n, '.'); i > 0 {
				n = n[:i]
			}
			h.Nom = strings.ToUpper(n)
		}
		var ostype string
		for _, xp := range xh.Ports {
			if xp.State.State != "open" {
				continue
			}
			p := Port{Port: xp.PortID, Proto: xp.Protocol, Service: xp.Service.Name, Produit: xp.Service.Product,
				Version: xp.Service.Version}
			if xp.Service.OSType != "" {
				ostype = xp.Service.OSType
			}
			for _, sc := range xp.Scripts {
				switch sc.ID {
				case "ftp-anon":
					v := strings.Contains(sc.Output, "Anonymous FTP login allowed")
					h.FtpAnonyme = &v
				case "http-auth":
					v := strings.Contains(sc.Output, "401") || strings.Contains(strings.ToLower(sc.Output), "authentication")
					p.HTTPAuthRequise = &v
				case "rdp-enum-encryption":
					if v, ok := nlaDepuisSortie(sc.Output); ok {
						h.RdpNla = &v
					}
				}
			}
			h.Ports = append(h.Ports, p)
		}
		for _, sc := range xh.HostScripts {
			switch sc.ID {
			case "smb-protocols":
				if h.Smb == nil {
					h.Smb = &Smb{}
				}
				for _, m := range rxDialecte.FindAllStringSubmatch(sc.Output, -1) {
					h.Smb.Dialectes = append(h.Smb.Dialectes, strings.ReplaceAll(m[1], ":", "."))
				}
			case "smb2-security-mode":
				if h.Smb == nil {
					h.Smb = &Smb{}
				}
				o := strings.ToLower(sc.Output)
				v := strings.Contains(o, "enabled and required")
				if v || strings.Contains(o, "not required") || strings.Contains(o, "disabled") {
					h.Smb.SignatureRequise = &v
				}
			case "smb-os-discovery":
				if os := sc.elem("os"); os != "" {
					h.OS = &SystemeExploitation{Nom: os}
				}
				if h.Nom == "" {
					h.Nom = strings.ToUpper(sc.elem("server"))
				}
			case "nbstat":
				if h.Nom == "" {
					h.Nom = strings.ToUpper(sc.elem("server_name"))
				}
			}
		}
		if h.OS == nil && ostype != "" {
			h.OS = &SystemeExploitation{Nom: ostype}
		}
		if len(h.Ports) == 0 && h.Smb == nil {
			continue
		}
		DevinerType(&h)
		res = append(res, h)
	}
	return res, map[string]any{"version": run.Version}, nil
}

// nlaDepuisSortie : NLA est considérée comme exigée si seule la couche CredSSP est acceptée.
func nlaDepuisSortie(sortie string) (bool, bool) {
	o := strings.ToLower(sortie)
	if !strings.Contains(o, "credssp") {
		return false, false
	}
	natif := regexp.MustCompile(`(native rdp|ssl)\s*:\s*success`).MatchString(o)
	return !natif, true
}

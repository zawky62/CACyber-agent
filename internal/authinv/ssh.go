package authinv

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"cacyber/agent/internal/scan"
)

// CommandesSSH : SEULES commandes exécutées par SSH (lecture seule, liste blanche testée). Chacune
// dans sa propre session, sortie bornée à 4 Mio.
var CommandesSSH = map[string]string{
	"os":       "cat /etc/os-release",
	"noyau":    "uname -r",
	"paquets":  `dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null || rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null`,
	"sshd":     "cat /etc/ssh/sshd_config 2>/dev/null",
	"sudoers":  "test -e /etc/sudoers && echo present",
}

// Mots interdits dans une commande SSH (écriture, téléchargement, élévation, exécution indirecte).
var motsInterditsSSH = []string{" rm ", "mv ", "cp ", ">", "tee", "chmod", "chown", "sudo ", "su ", "curl", "wget",
	"apt ", "yum ", "dnf ", "systemctl", "kill", "eval", "exec ", "bash -c", "sh -c", "dd ", "mkfs", "passwd"}

// CommandeLectureSeule vérifie qu'une commande ne contient aucune opération d'écriture ou d'exécution.
func CommandeLectureSeule(c string) error {
	l := " " + strings.ToLower(c) + " "
	for _, m := range motsInterditsSSH {
		if strings.Contains(strings.ReplaceAll(l, "2>/dev/null", ""), m) {
			return fmt.Errorf("commande SSH interdite (%q) : %s", strings.TrimSpace(m), c)
		}
	}
	return nil
}

func inventaireSSH(ctx context.Context, ip string, o Options) (resultat, error) {
	for _, c := range CommandesSSH {
		if err := CommandeLectureSeule(c); err != nil {
			return resultat{}, err
		}
	}
	// Vérification de la clé d'hôte AVANT tout envoi du mot de passe : fermée par défaut. Sans fichier
	// known_hosts de l'entité, l'inventaire SSH est refusé, sauf acceptation explicite et journalisée.
	var empreinte string
	var verif ssh.HostKeyCallback
	switch {
	case o.SSHHotesConnus != "":
		kh, err := knownhosts.New(o.SSHHotesConnus)
		if err != nil {
			return resultat{}, fmt.Errorf("fichier known_hosts illisible : %w", err)
		}
		verif = func(h string, a net.Addr, cle ssh.PublicKey) error {
			empreinte = ssh.FingerprintSHA256(cle)
			return kh(h, a, cle)
		}
	case o.SSHClesNonVerifiees:
		verif = func(_ string, _ net.Addr, cle ssh.PublicKey) error {
			empreinte = ssh.FingerprintSHA256(cle) // relevée et transmise (traçabilité de l'hôte interrogé)
			return nil
		}
		if o.Journal != nil {
			o.Journal(fmt.Sprintf("%s : clé d'hôte SSH acceptée SANS vérification (option explicite).", ip))
		}
	default:
		return resultat{}, errors.New("inventaire SSH refusé : fournissez le fichier known_hosts de l'entité " +
			"(--ssh-known-hosts) pour authentifier les serveurs avant d'y envoyer un mot de passe")
	}
	var client *ssh.Client
	err := o.Linux.Avec(func(mdp string) error {
		cfg := &ssh.ClientConfig{User: o.Linux.Utilisateur, Auth: []ssh.AuthMethod{ssh.Password(mdp)},
			HostKeyCallback: verif, Timeout: o.Delai}
		d := net.Dialer{Timeout: o.Delai}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "22"))
		if err != nil {
			return err
		}
		c, ch, req, err := ssh.NewClientConn(conn, ip, cfg)
		if err != nil {
			_ = conn.Close()
			return err
		}
		client = ssh.NewClient(c, ch, req)
		return nil
	})
	if err != nil {
		return resultat{}, err
	}
	defer client.Close()
	sorties := map[string][]byte{}
	for nom, cmd := range CommandesSSH {
		if ctx.Err() != nil {
			return resultat{}, ctx.Err()
		}
		s, err := client.NewSession()
		if err != nil {
			return resultat{}, err
		}
		var out bytes.Buffer
		s.Stdout = &limite{w: &out, n: 4 << 20}
		_ = s.Run(cmd) // un échec (commande absente) laisse une sortie vide
		_ = s.Close()
		sorties[nom] = out.Bytes()
	}
	r := analyserSSH(sorties)
	r.empreinte = empreinte
	return r, nil
}

// analyserSSH : interprétation des sorties (aucune autre donnée n'est conservée).
func analyserSSH(s map[string][]byte) resultat {
	var r resultat
	rel := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(s["os"]))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			rel[k] = strings.Trim(v, `"'`)
		}
	}
	nom := rel["PRETTY_NAME"]
	if nom == "" {
		nom = rel["NAME"]
	}
	if nom != "" {
		r.os = &scan.SystemeExploitation{Nom: nom, Version: rel["VERSION_ID"], Build: strings.TrimSpace(string(s["noyau"]))}
	}
	sc = bufio.NewScanner(bytes.NewReader(s["paquets"]))
	for sc.Scan() && len(r.logiciels) < scan.MaxLogiciels {
		if n, v, ok := strings.Cut(sc.Text(), "\t"); ok && n != "" {
			r.logiciels = append(r.logiciels, scan.Logiciel{Nom: n, Version: v})
		}
	}
	racine, mdp := false, true // valeurs par défaut d'OpenSSH récent : racine par clé seulement, mot de passe admis
	if len(s["sshd"]) > 0 {
		sc = bufio.NewScanner(bytes.NewReader(s["sshd"]))
		for sc.Scan() {
			ch := strings.Fields(strings.ToLower(strings.SplitN(sc.Text(), "#", 2)[0]))
			if len(ch) < 2 {
				continue
			}
			switch ch[0] {
			case "permitrootlogin":
				racine = ch[1] == "yes"
			case "passwordauthentication":
				mdp = ch[1] == "yes"
			}
		}
		r.racineSSH, r.mdpSSH = &racine, &mdp
	}
	return r
}

// limite : écrit au plus n octets (sortie bornée).
type limite struct {
	w io.Writer
	n int
}

func (l *limite) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	k := len(p)
	if k > l.n {
		p = p[:l.n]
	}
	l.n -= len(p)
	if _, err := l.w.Write(p); err != nil {
		return 0, err
	}
	return k, nil
}


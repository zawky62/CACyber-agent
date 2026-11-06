package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"cacyber/agent/internal/authinv"
	"cacyber/agent/internal/identifiants"
	"cacyber/agent/internal/journal"
)

// Options des collectes complémentaires (mode console). Aucun mot de passe n'est accepté en argument
// ni en variable d'environnement (visibles par d'autres processus) : il est SAISI au clavier, sans
// écho, gardé en mémoire et effacé après la collecte.
var (
	optDomaineAD     = flag.String("domaine-ad", "", "nom DNS du domaine Active Directory (par défaut : celui du poste)")
	optIdentAD       = flag.Bool("identifiants-ad", false, "saisir un compte de domaine pour lire l'annuaire (sinon : identité Windows courante)")
	optIdentWindows  = flag.Bool("identifiants-windows", false, "saisir un compte d'administration Windows pour l'inventaire authentifié (WinRM)")
	optIdentLinux    = flag.Bool("identifiants-linux", false, "saisir un compte SSH pour l'inventaire authentifié des serveurs Linux")
	optWinRMHTTP     = flag.Bool("winrm-http", false, "autoriser WinRM sur HTTP (5985, NTLM) si HTTPS (5986) est indisponible")
	optWinRMNonVerif = flag.Bool("winrm-certificat-non-verifie", false, "accepter un certificat WinRM autosigné (déconseillé)")
	optSSHConnus     = flag.String("ssh-known-hosts", "", "fichier known_hosts de l'entité (OBLIGATOIRE pour l'inventaire SSH) : toute clé inconnue est refusée")
	optSSHNonVerif   = flag.Bool("ssh-cles-non-verifiees", false, "accepter des clés d'hôte SSH non vérifiées (déconseillé : risque d'interception du mot de passe)")
)

// complementsDepuisOptions saisit les identifiants demandés et prépare les collectes complémentaires.
func complementsDepuisOptions() (journal.Complements, error) {
	c := journal.Complements{DomaineAD: *optDomaineAD, Auth: authinv.Options{
		WinRMHTTP: *optWinRMHTTP, WinRMCertificatNonVerifie: *optWinRMNonVerif, SSHHotesConnus: *optSSHConnus, SSHClesNonVerifiees: *optSSHNonVerif}}
	var err error
	if *optIdentAD {
		if c.IdentifiantsAD, err = saisir("Compte de domaine pour la lecture de l'annuaire"); err != nil {
			return c, err
		}
	}
	if *optIdentWindows {
		if c.Auth.Windows, err = saisir("Compte d'administration Windows (inventaire WinRM)"); err != nil {
			return c, err
		}
	}
	if *optIdentLinux {
		if c.Auth.Linux, err = saisir("Compte SSH (inventaire des serveurs Linux)"); err != nil {
			return c, err
		}
	}
	return c, nil
}

// saisir : compte (DOMAINE\utilisateur ou utilisateur@domaine) puis mot de passe sans écho.
func saisir(libelle string) (*identifiants.Identifiants, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("saisie des identifiants : une console interactive est requise")
	}
	fmt.Printf("%s\n  Compte : ", libelle)
	compte, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return nil, err
	}
	fmt.Print("  Mot de passe (non affiché, jamais enregistré ni transmis au serveur) : ")
	mdp, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	if len(mdp) == 0 {
		return nil, errors.New("mot de passe vide")
	}
	return identifiants.Nouveaux("", strings.TrimSpace(compte), mdp), nil // mdp effacé par Nouveaux
}

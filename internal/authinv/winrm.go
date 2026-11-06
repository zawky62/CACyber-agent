package authinv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/masterzen/winrm"

	"cacyber/agent/internal/scan"
)

// ScriptWindows : SEUL script exécuté par WinRM (lecture seule, sortie JSON compacte). Il lit le
// système, les logiciels installés (clés « Uninstall »), les correctifs, les administrateurs locaux,
// l'état du pare-feu, du chiffrement BitLocker du volume système et de l'antivirus. Les lectures qui
// exigent des droits absents échouent silencieusement (valeur nulle).
const ScriptWindows = `$ErrorActionPreference='SilentlyContinue'
$o=Get-CimInstance Win32_OperatingSystem
$cles='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$l=Get-ItemProperty $cles | Where-Object {$_.DisplayName} | ForEach-Object {@{n=[string]$_.DisplayName;v=[string]$_.DisplayVersion;e=[string]$_.Publisher}}
$h=Get-HotFix | ForEach-Object {@{kb=[string]$_.HotFixID;d=$(if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}else{''})}}
$a=Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {[string]$_.Name}
$f=$null;$p=Get-NetFirewallProfile;if($p){$f=-not ($p | Where-Object {-not $_.Enabled})}
$b=$null;$v=Get-CimInstance -Namespace root\cimv2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'";if($v){$b=($v.ProtectionStatus -eq 1)}
$av=Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -First 1
$r=@{os=@{nom=[string]$o.Caption;version=[string]$o.Version;build=[string]$o.BuildNumber};logiciels=@($l);correctifs=@($h);admins=@($a);pare_feu=$f;bitlocker=$b;antivirus=$(if($av){[string]$av.displayName}else{$null})}
$r | ConvertTo-Json -Compress -Depth 4`

// Cmdlets et commandes qui modifieraient le système : interdits dans le script (vérifié par les tests).
var rxEcriture = regexp.MustCompile(`(?i)\b(Set-|New-|Remove-|Add-|Clear-|Rename-|Move-|Copy-|Start-|Stop-|Restart-|Install-|Uninstall-|Enable-|Disable-|Invoke-(Expression|WebRequest|RestMethod|Command|Item)|Out-File|Export-|Register-|Unregister-|reg\s+(add|delete)|sc\s+(config|create|delete)|net\s+user|iex\b)`)

// ScriptLectureSeule vérifie qu'un script ne contient aucune commande d'écriture.
func ScriptLectureSeule(s string) error {
	if m := rxEcriture.FindString(s); m != "" {
		return fmt.Errorf("commande d'écriture interdite dans le script : %q", m)
	}
	return nil
}

type sortieWindows struct {
	OS         *scan.SystemeExploitation `json:"os"`
	Logiciels  []struct{ N, V, E string } `json:"logiciels"`
	Correctifs []struct {
		KB string `json:"kb"`
		D  string `json:"d"`
	} `json:"correctifs"`
	Admins    []string `json:"admins"`
	PareFeu   *bool    `json:"pare_feu"`
	BitLocker *bool    `json:"bitlocker"`
	Antivirus *string  `json:"antivirus"`
}

func inventaireWinRM(ctx context.Context, ip string, ports []scan.Port, o Options) (resultat, error) {
	if err := ScriptLectureSeule(ScriptWindows); err != nil {
		return resultat{}, err
	}
	https := false
	for _, p := range ports {
		if p.Port == 5986 {
			https = true
		}
	}
	port := 5985
	if https {
		port = 5986
	} else if !o.WinRMHTTP {
		return resultat{}, errors.New("WinRM HTTPS indisponible (HTTP non autorisé)")
	}
	ep := winrm.NewEndpoint(ip, port, https, o.WinRMCertificatNonVerifie, nil, nil, nil, o.Delai)
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} } // NTLM : mot de passe jamais transmis
	var sortie, erreurs string
	var code int
	err := o.Windows.Avec(func(mdp string) error {
		util := o.Windows.Utilisateur
		if o.Windows.Domaine != "" {
			util = o.Windows.Domaine + `\` + util
		}
		cl, err := winrm.NewClientWithParameters(ep, util, mdp, params)
		if err != nil {
			return err
		}
		sortie, erreurs, code, err = cl.RunWithContextWithString(ctx, winrm.Powershell(ScriptWindows), "")
		return err
	})
	if err != nil {
		return resultat{}, err
	}
	if code != 0 && strings.TrimSpace(sortie) == "" {
		return resultat{}, fmt.Errorf("script refusé par l'hôte (code %d) : %s", code, nettoyer(erreurs))
	}
	return analyserWindows([]byte(sortie))
}

// analyserWindows : lecture de la sortie JSON du script (taille bornée).
func analyserWindows(b []byte) (resultat, error) {
	if len(b) > 8<<20 {
		return resultat{}, errors.New("sortie WinRM trop volumineuse")
	}
	var s sortieWindows
	if err := json.Unmarshal(b, &s); err != nil {
		return resultat{}, fmt.Errorf("sortie WinRM illisible : %w", err)
	}
	r := resultat{os: s.OS, admins: s.Admins, pareFeu: s.PareFeu, chiffrement: s.BitLocker}
	for _, l := range s.Logiciels {
		if l.N != "" && len(r.logiciels) < scan.MaxLogiciels {
			r.logiciels = append(r.logiciels, scan.Logiciel{Nom: l.N, Version: l.V, Editeur: l.E})
		}
	}
	for _, c := range s.Correctifs {
		if c.KB == "" || len(r.correctifs) >= scan.MaxCorrectifs {
			continue
		}
		cc := scan.Correctif{KB: c.KB}
		if len(c.D) == 10 {
			d := c.D
			cc.InstalleLe = &d
		}
		r.correctifs = append(r.correctifs, cc)
	}
	if s.Antivirus != nil && *s.Antivirus != "" {
		r.antivirus = &scan.Antivirus{Produit: *s.Antivirus, Actif: true}
	}
	return r, nil
}

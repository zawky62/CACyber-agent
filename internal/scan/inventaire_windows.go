//go:build windows

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Inventaire local du poste Windows qui exécute l'agent.
//
// Chaque information est lue par une commande PowerShell / système CONSTANTE, définie ci-dessous :
// aucune chaîne venant du serveur ou du réseau n'est jamais exécutée. Toutes les commandes sont
// en lecture seule (Get-*, net accounts, auditpol /get). Certaines exigent des droits
// d'administrateur : en leur absence, l'information est simplement « non collectée ».

const prefixePS = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; "

// Commandes figées (lecture seule).
const (
	psSysteme = `Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress`

	psLogiciels = `$c='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*';` +
		` Get-ItemProperty $c -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |` +
		` Select-Object DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Compress`

	psCorrectifs = `Get-HotFix | Select-Object HotFixID,@{n='d';e={ if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } }} | ConvertTo-Json -Compress`

	psDefender = `Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress`

	psCentreSecurite = `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json -Compress`

	psComptes = `Get-LocalUser | Select-Object Name,Enabled,@{n='Sid';e={$_.SID.Value}} | ConvertTo-Json -Compress`

	psAdministrateurs = `Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,@{n='Sid';e={$_.SID.Value}} | ConvertTo-Json -Compress`

	// Partages non spéciaux et présence d'un droit d'écriture accordé à « Tout le monde » (SID S-1-1-0).
	psPartages = `Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { $s=$_;` +
		` $w = @(Get-SmbShareAccess -Name $s.Name | Where-Object { $_.AccessControlType -eq 'Allow' -and ("$($_.AccessRight)" -in 'Full','Change') -and` +
		` ((New-Object System.Security.Principal.NTAccount($_.AccountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0') }).Count -gt 0;` +
		` [pscustomobject]@{Name=$s.Name;Path=$s.Path;Ecriture=$w} } | ConvertTo-Json -Compress`

	// Sauvegarde Windows Server : équivalent PowerShell en lecture seule de « wbadmin get versions ».
	psSauvegardes = `if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) { Get-WBSummary |` +
		` Select-Object @{n='Derniere';e={ if ($_.LastSuccessfulBackupTime -gt [datetime]'2000-01-01') { $_.LastSuccessfulBackupTime.ToString('o') } }},NumberOfVersions | ConvertTo-Json -Compress } else { 'absent' }`

	// Taille maximale du journal de sécurité (registre, lisible sans droits d'administrateur).
	psJournal = `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name MaxSize).MaxSize`
)

// Sous-catégorie d'audit « Ouverture de session » désignée par son GUID : indépendant de la langue.
var argsAuditpol = []string{"/get", "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}", "/r"}

func powershell(ctx context.Context, script string) ([]byte, error) {
	ctx, annuler := context.WithTimeout(ctx, 60*time.Second)
	defer annuler()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", prefixePS+script)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if i := strings.IndexByte(msg, '\n'); i > 0 {
			msg = msg[:i]
		}
		return nil, fmt.Errorf("%v %s", err, msg)
	}
	return bytes.TrimSpace(bytes.TrimPrefix(out, []byte("\xef\xbb\xbf"))), nil
}

// enListe décode un résultat ConvertTo-Json qui peut être un objet seul ou un tableau.
func enListe[T any](data []byte) ([]T, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] == '[' {
		var l []T
		return l, json.Unmarshal(data, &l)
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return []T{v}, nil
}

// CollecterInventaire lit l'inventaire du poste. `note` reçoit un message lisible par
// information non collectée (droits insuffisants, module absent…), qui est journalisé.
func CollecterInventaire(ctx context.Context, note func(string)) (*Inventaire, *SystemeExploitation) {
	inv := &Inventaire{}
	var sys *SystemeExploitation

	// Système d'exploitation
	if out, err := powershell(ctx, psSysteme); err == nil {
		var o struct{ Caption, Version, BuildNumber string }
		if json.Unmarshal(out, &o) == nil {
			sys = &SystemeExploitation{Nom: strings.TrimSpace(strings.TrimPrefix(o.Caption, "Microsoft ")), Version: o.Version, Build: o.BuildNumber}
		}
	} else {
		note("Système d'exploitation non lu : " + err.Error())
	}

	// Logiciels installés
	if out, err := powershell(ctx, psLogiciels); err == nil {
		l, _ := enListe[struct{ DisplayName, DisplayVersion, Publisher string }](out)
		vus := map[string]bool{}
		for _, x := range l {
			k := x.DisplayName + "|" + x.DisplayVersion
			if vus[k] {
				continue
			}
			vus[k] = true
			inv.Logiciels = append(inv.Logiciels, Logiciel{Nom: x.DisplayName, Version: x.DisplayVersion, Editeur: x.Publisher})
		}
	} else {
		note("Inventaire logiciel non lu : " + err.Error())
	}

	// Correctifs
	if out, err := powershell(ctx, psCorrectifs); err == nil {
		l, _ := enListe[struct {
			HotFixID string
			D        *string `json:"d"`
		}](out)
		for _, x := range l {
			inv.Correctifs = append(inv.Correctifs, Correctif{KB: x.HotFixID, InstalleLe: x.D})
		}
	} else {
		note("Liste des correctifs non lue : " + err.Error())
	}

	// Antivirus : Microsoft Defender, sinon Centre de sécurité (postes uniquement)
	if out, err := powershell(ctx, psDefender); err == nil {
		var o struct {
			AntivirusEnabled, RealTimeProtectionEnabled bool
			AntivirusSignatureAge                       int
		}
		if json.Unmarshal(out, &o) == nil {
			tr, age := o.RealTimeProtectionEnabled, o.AntivirusSignatureAge
			inv.Antivirus = &Antivirus{Produit: "Microsoft Defender", Actif: o.AntivirusEnabled, TempsReel: &tr, SignaturesAgeJours: &age}
		}
	}
	if inv.Antivirus == nil || !inv.Antivirus.Actif {
		if out, err := powershell(ctx, psCentreSecurite); err == nil {
			l, _ := enListe[struct {
				DisplayName  string `json:"displayName"`
				ProductState int    `json:"productState"`
			}](out)
			for _, x := range l {
				// productState : bits 12-15 = état (1 = actif), bits 4-7 = signatures (0 = à jour).
				actif := (x.ProductState>>12)&0xF == 1
				if actif || inv.Antivirus == nil {
					inv.Antivirus = &Antivirus{Produit: x.DisplayName, Actif: actif}
					if (x.ProductState>>4)&0xF != 0 {
						vieux := 8 // signatures signalées périmées par Windows, âge exact inconnu
						inv.Antivirus.SignaturesAgeJours = &vieux
					}
				}
			}
		} else if inv.Antivirus == nil {
			note("État de l'antivirus non lu : " + err.Error())
		}
	}

	// Politique de mots de passe et de verrouillage
	if out, err := exec.CommandContext(ctx, "net", "accounts").Output(); err == nil {
		inv.PolitiqueMdp = AnalyserNetAccounts(string(out))
	} else {
		note("Politique de mots de passe non lue : " + err.Error())
	}

	// Comptes locaux et administrateurs
	if out, err := powershell(ctx, psComptes); err == nil {
		comptes, _ := enListe[struct {
			Name    string
			Enabled bool
			Sid     string
		}](out)
		admins := map[string]bool{}
		if out2, err2 := powershell(ctx, psAdministrateurs); err2 == nil {
			l, _ := enListe[struct{ Name, Sid string }](out2)
			for _, a := range l {
				admins[a.Sid] = true
			}
		} else {
			note("Membres du groupe Administrateurs non lus : " + err2.Error())
		}
		for _, c := range comptes {
			inv.Comptes = append(inv.Comptes, Compte{Nom: c.Name, Actif: c.Enabled, Admin: admins[c.Sid],
				Integre: strings.HasSuffix(c.Sid, "-500")})
		}
	} else {
		note("Comptes locaux non lus : " + err.Error())
	}

	// Partages
	if out, err := powershell(ctx, psPartages); err == nil {
		l, _ := enListe[struct {
			Name, Path string
			Ecriture   bool
		}](out)
		for _, x := range l {
			inv.Partages = append(inv.Partages, Partage{Nom: x.Name, Chemin: x.Path, EcritureToutLeMonde: x.Ecriture})
		}
	} else {
		note("Partages non lus (droits d'administrateur requis) : " + err.Error())
	}

	// Sauvegardes (Sauvegarde Windows Server, si présente)
	if out, err := powershell(ctx, psSauvegardes); err == nil {
		if s := string(out); s != "absent" && s != "" {
			var o struct {
				Derniere         *string
				NumberOfVersions int
			}
			if json.Unmarshal(out, &o) == nil {
				nb := o.NumberOfVersions
				inv.Sauvegardes = &Sauvegardes{Outil: "Sauvegarde Windows Server", Derniere: o.Derniere, NbVersions: &nb}
			}
		}
	} else {
		note("Historique des sauvegardes non lu : " + err.Error())
	}

	// Journalisation
	jn := &Journalisation{}
	if out, err := powershell(ctx, psJournal); err == nil {
		if octets, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			mo := int(octets / (1024 * 1024))
			jn.TailleMaxMo = &mo
		}
	}
	if out, err := exec.CommandContext(ctx, "auditpol", argsAuditpol...).Output(); err == nil {
		if v, ok := AnalyserAuditpol(string(out)); ok {
			jn.AuditConnexions = &v
		}
	} else {
		note("Politique d'audit des connexions non lue (droits d'administrateur requis).")
	}
	if jn.TailleMaxMo != nil || jn.AuditConnexions != nil {
		inv.Journalisation = jn
	}
	return inv, sys
}

var rxNombre = regexp.MustCompile(`(\d+)\s*$`)

// AnalyserNetAccounts lit la sortie de « net accounts » (anglais ou français).
// « Jamais / Never / Illimité / Unlimited » valent 0.
func AnalyserNetAccounts(sortie string) *PolitiqueMdp {
	p := &PolitiqueMdp{}
	for _, ligne := range strings.Split(sortie, "\n") {
		l := strings.ToLower(strings.TrimSpace(ligne))
		i := strings.LastIndex(l, ":")
		if i < 0 {
			continue
		}
		val := 0
		if m := rxNombre.FindStringSubmatch(strings.TrimSpace(l[i+1:])); m != nil {
			val, _ = strconv.Atoi(m[1])
		}
		cle := l[:i]
		switch {
		case strings.Contains(cle, "minimum password length") || strings.Contains(cle, "longueur minimale"):
			p.LongueurMin = &val
		case strings.Contains(cle, "maximum password age") || strings.Contains(cle, "maximale du mot de passe"):
			v := val
			p.ExpirationJours = &v
		case strings.Contains(cle, "lockout threshold") || strings.Contains(cle, "seuil de verrouillage"):
			v := val
			p.SeuilVerrouillage = &v
		}
	}
	return p
}

// AnalyserAuditpol lit la sortie CSV (/r) : la dernière colonne « Setting Value » vaut
// 0 (aucun audit), 1 (succès), 2 (échec) ou 3 (succès et échec).
func AnalyserAuditpol(sortie string) (bool, bool) {
	for _, ligne := range strings.Split(sortie, "\n") {
		champs := strings.Split(strings.TrimSpace(ligne), ",")
		if len(champs) < 5 || !strings.Contains(strings.ToUpper(ligne), "0CCE9215") {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(champs[len(champs)-1])); err == nil {
			return v&1 == 1, true
		}
	}
	return false, false
}

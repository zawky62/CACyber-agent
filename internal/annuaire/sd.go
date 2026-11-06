// Package annuaire collecte, EN LECTURE SEULE et par LDAP chiffré (LDAPS ou StartTLS), les faits de
// l'annuaire Active Directory nécessaires à l'audit : comptes, groupes, ordinateurs, appartenances,
// indicateurs de compte, délégations, politique de mots de passe, présence de LAPS et listes de
// contrôle d'accès (DACL) des objets. Il remplace le collecteur SharpHound (binaire signalé par les
// antivirus) par un code propre à l'agent, signé avec lui.
//
// Aucune écriture, aucune requête Kerberos de ticket de service, aucun attribut secret (mots de passe
// LAPS, empreintes de mots de passe) n'est jamais demandé : la liste des attributs est fermée et
// vérifiée par les tests. L'analyse (chemins d'élévation de privilèges, constats) est faite par le
// serveur CACyber, jamais par l'agent.
package annuaire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// SIDTexte convertit un SID binaire en forme textuelle « S-1-5-21-… ».
func SIDTexte(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 {
		return "", errors.New("SID invalide")
	}
	n := int(b[1])
	if len(b) < 8+4*n {
		return "", errors.New("SID tronqué")
	}
	var autorite uint64
	for _, x := range b[2:8] {
		autorite = autorite<<8 | uint64(x)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-1-%d", autorite)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String(), nil
}

// GUIDTexte : GUID binaire (ordre Windows, trois premiers champs en petit-boutiste) -> texte.
func GUIDTexte(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

// Droits d'accès (masques) et GUID des droits étendus / attributs examinés.
const (
	droitGenericAll   = 0x10000000
	droitGenericWrite = 0x40000000
	droitControleTot  = 0x000F01FF // ensemble des droits d'annuaire (contrôle total)
	droitWriteDac     = 0x00040000
	droitWriteOwner   = 0x00080000
	droitWriteProp    = 0x00000020
	droitSelf         = 0x00000008
	droitExtended     = 0x00000100

	guidForceChangePwd = "00299570-246d-11d0-a768-00aa006e0529"
	guidMember         = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	guidGetChanges     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidGetChangesAll  = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	guidKeyCredLink    = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
)

// Droit : un droit de contrôle accordé à un principal sur l'objet décrit.
type Droit struct {
	SID  string
	Type string // GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, ForceChangePassword,
	// AddMember, AddSelf, AddKeyCredentialLink, GetChanges, GetChangesAll
}

// Descripteur : propriétaire et droits utiles extraits d'un nTSecurityDescriptor.
type Descripteur struct {
	Proprietaire string
	Droits       []Droit
}

// AnalyserDescripteur lit un descripteur de sécurité auto-relatif (format binaire MS-DTYP) et en
// extrait le propriétaire et les ACE d'AUTORISATION effectives sur l'objet lui-même (les ACE
// « héritage seulement » sont ignorées ; les ACE de refus aussi, comme le fait BloodHound : l'analyse
// peut donc surestimer un chemin, jamais le masquer).
func AnalyserDescripteur(sd []byte, estGroupe bool) (Descripteur, error) {
	var d Descripteur
	if len(sd) < 20 || sd[0] != 1 {
		return d, errors.New("descripteur de sécurité invalide")
	}
	offProp := binary.LittleEndian.Uint32(sd[4:8])
	offDacl := binary.LittleEndian.Uint32(sd[16:20])
	if offProp != 0 && int(offProp) < len(sd) {
		if s, err := SIDTexte(sd[offProp:]); err == nil {
			d.Proprietaire = s
		}
	}
	if offDacl == 0 || int(offDacl)+8 > len(sd) {
		return d, nil // aucune DACL lisible
	}
	acl := sd[offDacl:]
	n := int(binary.LittleEndian.Uint16(acl[4:6]))
	pos := 8
	for i := 0; i < n && pos+4 <= len(acl); i++ {
		typ, drapeaux := acl[pos], acl[pos+1]
		taille := int(binary.LittleEndian.Uint16(acl[pos+2 : pos+4]))
		if taille < 8 || pos+taille > len(acl) {
			return d, errors.New("ACE tronquée")
		}
		ace := acl[pos : pos+taille]
		pos += taille
		if drapeaux&0x08 != 0 { // INHERIT_ONLY_ACE : ne s'applique pas à l'objet lui-même
			continue
		}
		masque := binary.LittleEndian.Uint32(ace[4:8])
		switch typ {
		case 0x00: // ACCESS_ALLOWED_ACE
			sid, err := SIDTexte(ace[8:])
			if err != nil {
				continue
			}
			d.Droits = append(d.Droits, droitsGeneraux(sid, masque, estGroupe)...)
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE
			if len(ace) < 12 {
				continue
			}
			flags := binary.LittleEndian.Uint32(ace[8:12])
			k := 12
			objet := ""
			if flags&0x1 != 0 {
				if len(ace) < k+16 {
					continue
				}
				objet = GUIDTexte(ace[k : k+16])
				k += 16
			}
			if flags&0x2 != 0 {
				k += 16
			}
			if len(ace) <= k {
				continue
			}
			sid, err := SIDTexte(ace[k:])
			if err != nil {
				continue
			}
			if objet == "" {
				d.Droits = append(d.Droits, droitsGeneraux(sid, masque, estGroupe)...)
			} else {
				d.Droits = append(d.Droits, droitsObjet(sid, masque, objet, estGroupe)...)
			}
		}
	}
	return d, nil
}

// droitsGeneraux : ACE sans type d'objet (s'applique à toutes les propriétés / tous les droits étendus).
func droitsGeneraux(sid string, m uint32, estGroupe bool) []Droit {
	if m&droitGenericAll != 0 || m&droitControleTot == droitControleTot {
		return []Droit{{sid, "GenericAll"}}
	}
	var r []Droit
	if m&droitGenericWrite != 0 || m&droitWriteProp != 0 {
		r = append(r, Droit{sid, "GenericWrite"})
	}
	if m&droitWriteDac != 0 {
		r = append(r, Droit{sid, "WriteDacl"})
	}
	if m&droitWriteOwner != 0 {
		r = append(r, Droit{sid, "WriteOwner"})
	}
	if m&droitExtended != 0 {
		r = append(r, Droit{sid, "AllExtendedRights"})
	}
	if estGroupe && m&droitSelf != 0 {
		r = append(r, Droit{sid, "AddSelf"})
	}
	return r
}

// droitsObjet : ACE limitée à un attribut ou à un droit étendu précis.
func droitsObjet(sid string, m uint32, objet string, estGroupe bool) []Droit {
	switch {
	case objet == guidForceChangePwd && m&droitExtended != 0:
		return []Droit{{sid, "ForceChangePassword"}}
	case objet == guidGetChanges && m&droitExtended != 0:
		return []Droit{{sid, "GetChanges"}}
	case objet == guidGetChangesAll && m&droitExtended != 0:
		return []Droit{{sid, "GetChangesAll"}}
	case objet == guidMember && estGroupe && m&droitWriteProp != 0:
		return []Droit{{sid, "AddMember"}}
	case objet == guidMember && estGroupe && m&droitSelf != 0:
		return []Droit{{sid, "AddSelf"}}
	case objet == guidKeyCredLink && m&droitWriteProp != 0:
		return []Droit{{sid, "AddKeyCredentialLink"}}
	}
	return nil
}

package outils

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Etape : progression affichée pendant l'installation (CLI et interface).
type Etape struct {
	Outil       string `json:"outil"`
	Texte       string `json:"texte"`
	Progression int    `json:"progression"` // 0..100, -1 si indéterminée
}

// EtatOutil : situation d'un composant après installation ou contrôle.
type EtatOutil struct {
	Nom        string `json:"nom"`
	Version    string `json:"version"`
	Licence    string `json:"licence"`
	Source     string `json:"source"`
	Chemin     string `json:"chemin,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Signataire string `json:"signataire,omitempty"`
	Pret       bool   `json:"pret"`
	Detail     string `json:"detail"`
}

// Gestionnaire : installe et vérifie l'outillage dans `Racine`.
type Gestionnaire struct {
	Racine  string
	Progres func(Etape)
	client  *http.Client
}

// hotesAutorises : seules origines de téléchargement admises (redirections comprises).
var hotesAutorises = map[string]bool{
	"github.com":                           true,
	"release-assets.githubusercontent.com": true,
	"objects.githubusercontent.com":        true,
	"raw.githubusercontent.com":            true,
	"nmap.org":                             true,
}

// DossierParDefaut : %LOCALAPPDATA%\CACyber\outils (installation par utilisateur, sans droits
// administrateur). Hors Windows : dossier de cache de l'utilisateur.
func DossierParDefaut() string {
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "CACyber", "outils")
		}
	}
	if c, err := os.UserCacheDir(); err == nil {
		return filepath.Join(c, "CACyber", "outils")
	}
	return filepath.Join(os.TempDir(), "CACyber-outils")
}

// Nouveau prépare le gestionnaire. `securiser` applique l'ACL protégée au dossier racine (fournie
// par le paquet etat, pour éviter une dépendance circulaire).
func Nouveau(racine string, securiser func(string) error, progres func(Etape)) (*Gestionnaire, error) {
	if securiser != nil {
		if err := securiser(racine); err != nil {
			return nil, err
		}
	} else if err := os.MkdirAll(racine, 0o700); err != nil {
		return nil, err
	}
	if progres == nil {
		progres = func(Etape) {}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	c := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("trop de redirections")
			}
			return verifierURL(req.URL)
		},
	}
	return &Gestionnaire{Racine: racine, Progres: progres, client: c}, nil
}

func verifierURL(u *url.URL) error {
	if u.Scheme != "https" || !hotesAutorises[u.Hostname()] {
		return fmt.Errorf("téléchargement refusé hors des sources officielles : %s", u.Host)
	}
	return nil
}

// Dossier d'installation d'un outil.
func (g *Gestionnaire) Dossier(o Outil) string { return filepath.Join(g.Racine, o.Nom, o.Version) }

// DossierModeles : modèles Nuclei de la liste blanche.
func (g *Gestionnaire) DossierModeles() string {
	return filepath.Join(g.Racine, "nuclei-modeles", strings.TrimPrefix(VersionModeles, "v"))
}

// Installer met en place osquery, Nuclei et les modèles Nuclei (idempotent : un composant déjà
// présent et intègre n'est pas retéléchargé ; un composant altéré est réinstallé).
func (g *Gestionnaire) Installer(ctx context.Context) ([]EtatOutil, error) {
	var res []EtatOutil
	var erreurs []string
	for _, o := range Geres {
		e, err := g.installerOutil(ctx, o)
		if err != nil {
			erreurs = append(erreurs, fmt.Sprintf("%s : %v", o.Nom, err))
			e = EtatOutil{Nom: o.Nom, Version: o.Version, Licence: o.Licence, Source: o.URL, Detail: err.Error()}
		}
		res = append(res, e)
	}
	e, err := g.installerModeles(ctx)
	if err != nil {
		erreurs = append(erreurs, "modèles nuclei : "+err.Error())
	}
	res = append(res, e)
	if len(erreurs) > 0 {
		return res, errors.New(strings.Join(erreurs, " ; "))
	}
	return res, nil
}

// Etat contrôle chaque composant sans rien télécharger (empreintes et signatures).
func (g *Gestionnaire) Etat() []EtatOutil {
	var res []EtatOutil
	for _, o := range Geres {
		x, err := g.Preparer(o)
		if err != nil {
			res = append(res, EtatOutil{Nom: o.Nom, Version: o.Version, Licence: o.Licence, Source: o.URL, Detail: err.Error()})
			continue
		}
		res = append(res, x.Etat("vérifié (empreinte" + map[bool]string{true: " et signature", false: ""}[x.Signataire != ""] + ")"))
		x.Fermer()
	}
	if err := g.verifierModeles(); err != nil {
		res = append(res, EtatOutil{Nom: "nuclei-modeles", Version: VersionModeles, Licence: "MIT", Detail: err.Error()})
	} else {
		res = append(res, g.etatModeles("vérifiés"))
	}
	return res
}

func (g *Gestionnaire) installerOutil(ctx context.Context, o Outil) (EtatOutil, error) {
	if x, err := g.Preparer(o); err == nil {
		e := x.Etat("déjà installé, intègre")
		x.Fermer()
		g.Progres(Etape{o.Nom, fmt.Sprintf("%s %s déjà installé et intègre.", o.Nom, o.Version), 100})
		return e, nil
	}
	g.Progres(Etape{o.Nom, fmt.Sprintf("Téléchargement de %s %s depuis la source officielle…", o.Nom, o.Version), 0})
	archive, err := g.telecharger(ctx, o.Nom, o.URL, o.SHA256, o.TailleMax)
	if err != nil {
		return EtatOutil{}, err
	}
	defer os.Remove(archive)
	g.Progres(Etape{o.Nom, "Empreinte SHA-256 de l'archive conforme : extraction…", 80})

	parent := filepath.Join(g.Racine, o.Nom)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return EtatOutil{}, err
	}
	travail, err := os.MkdirTemp(parent, "."+o.Version+"-")
	if err != nil {
		return EtatOutil{}, err
	}
	defer os.RemoveAll(travail)
	if err := extraire(archive, o.Fichiers, travail); err != nil {
		return EtatOutil{}, err
	}
	if err := ecrireProvenance(travail, o); err != nil {
		return EtatOutil{}, err
	}
	// Bascule atomique : l'ancien dossier (absent ou altéré) est remplacé d'un bloc.
	final := g.Dossier(o)
	if err := os.RemoveAll(final); err != nil {
		return EtatOutil{}, err
	}
	if err := os.Rename(travail, final); err != nil {
		return EtatOutil{}, fmt.Errorf("mise en place de %s : %w", final, err)
	}
	x, err := g.Preparer(o) // contrôle complet du résultat (empreinte + signature)
	if err != nil {
		return EtatOutil{}, err
	}
	defer x.Fermer()
	g.Progres(Etape{o.Nom, fmt.Sprintf("%s %s installé et vérifié.", o.Nom, o.Version), 100})
	return x.Etat("installé et vérifié"), nil
}

// telecharger écrit l'URL dans un fichier temporaire du dossier géré en calculant l'empreinte au
// fil de l'eau ; taille bornée ; fichier supprimé si l'empreinte diffère. Rien n'est exécuté ici.
func (g *Gestionnaire) telecharger(ctx context.Context, nom, adresse, sha string, max int64) (string, error) {
	u, err := url.Parse(adresse)
	if err != nil {
		return "", err
	}
	if err := verifierURL(u); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, adresse, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "CACyber-Agent (outillage open source)")
	rep, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("téléchargement de %s : %w", nom, err)
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return "", fmt.Errorf("téléchargement de %s : HTTP %d", nom, rep.StatusCode)
	}
	if rep.ContentLength > max {
		return "", fmt.Errorf("téléchargement de %s : taille annoncée excessive", nom)
	}
	dl := filepath.Join(g.Racine, ".telechargements")
	if err := os.MkdirAll(dl, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dl, nom+"-*.part")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	total := rep.ContentLength
	n, err := io.Copy(io.MultiWriter(f, h, &compteur{g: g, nom: nom, total: total}), io.LimitReader(rep.Body, max+1))
	if errF := f.Close(); err == nil {
		err = errF
	}
	if err == nil && n > max {
		err = fmt.Errorf("téléchargement de %s : taille excessive", nom)
	}
	if err == nil {
		if got := hex.EncodeToString(h.Sum(nil)); got != sha {
			err = fmt.Errorf("empreinte SHA-256 de %s NON CONFORME (attendu %s, obtenu %s) : fichier supprimé", nom, sha[:16], got[:16])
		}
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

type compteur struct {
	g        *Gestionnaire
	nom      string
	total, n int64
	dernier  int
}

func (c *compteur) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	if c.total > 0 {
		if pct := int(c.n * 75 / c.total); pct >= c.dernier+5 {
			c.dernier = pct
			c.g.Progres(Etape{c.nom, fmt.Sprintf("Téléchargement de %s : %d Mo", c.nom, c.n>>20), pct})
		}
	}
	return len(p), nil
}

// extraire ne retient que les membres de la liste blanche, vers des noms FIXÉS par le manifeste :
// aucun chemin issu de l'archive n'est utilisé pour écrire (pas de « zip slip » possible). Taille
// décompressée bornée, empreinte de chaque fichier contrôlée.
func extraire(archive string, fichiers []Fichier, dest string) error {
	z, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("archive illisible : %w", err)
	}
	defer z.Close()
	membres := map[string]*zip.File{}
	for _, f := range z.File {
		membres[f.Name] = f
	}
	for _, fi := range fichiers {
		if !filepath.IsLocal(fi.Dest) {
			return fmt.Errorf("destination non locale refusée : %q", fi.Dest)
		}
		zf, ok := membres[fi.Membre]
		if !ok {
			return fmt.Errorf("membre absent de l'archive : %s", fi.Membre)
		}
		if zf.Mode()&os.ModeSymlink != 0 || zf.FileInfo().IsDir() {
			return fmt.Errorf("membre de type inattendu : %s", fi.Membre)
		}
		if zf.UncompressedSize64 > uint64(fi.Taille) {
			return fmt.Errorf("membre trop volumineux : %s", fi.Membre)
		}
		if err := extraireUn(zf, fi, filepath.Join(dest, fi.Dest)); err != nil {
			return err
		}
	}
	return nil
}

func extraireUn(zf *zip.File, fi Fichier, cible string) error {
	r, err := zf.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	if err := os.MkdirAll(filepath.Dir(cible), 0o700); err != nil {
		return err
	}
	w, err := os.OpenFile(cible, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(r, fi.Taille+1))
	if errC := w.Close(); err == nil {
		err = errC
	}
	if err == nil && n > fi.Taille {
		err = fmt.Errorf("membre trop volumineux : %s", fi.Membre)
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != fi.SHA256 {
		err = fmt.Errorf("empreinte de %s non conforme", fi.Dest)
	}
	return err
}

// ecrireProvenance : fiche lisible remise avec l'outil (transparence, obligations de licence).
func ecrireProvenance(dossier string, o Outil) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Composant : %s %s\nLicence : %s (texte joint)\nSources : %s\nArchive officielle : %s\n",
		o.Nom, o.Version, o.Licence, o.URLSource, o.URL)
	fmt.Fprintf(&b, "SHA-256 de l'archive : %s\nOrigine de l'empreinte : %s\n", o.SHA256, o.SourceEmpreinte)
	for _, f := range o.Fichiers {
		fmt.Fprintf(&b, "SHA-256 %s : %s\n", f.Dest, f.SHA256)
	}
	if len(o.Signataires) > 0 {
		fmt.Fprintf(&b, "Signature Authenticode exigée : %s\n", strings.Join(o.Signataires, ", "))
	}
	fmt.Fprintf(&b, "Installé par CACyber-Agent le %s. Utilisation : lecture seule, sous mandat signé.\n",
		time.Now().Format("2006-01-02 15:04:05"))
	return os.WriteFile(filepath.Join(dossier, "PROVENANCE.txt"), []byte(b.String()), 0o600)
}

// ----------------------------------------------------------------------------- modèles Nuclei

func (g *Gestionnaire) installerModeles(ctx context.Context) (EtatOutil, error) {
	if g.verifierModeles() == nil {
		g.Progres(Etape{"nuclei-modeles", "Modèles Nuclei de la liste blanche déjà présents et intègres.", 100})
		return g.etatModeles("déjà installés, intègres"), nil
	}
	g.Progres(Etape{"nuclei-modeles", fmt.Sprintf("Téléchargement de %d modèles Nuclei non intrusifs (%s)…", len(ModelesNuclei), VersionModeles), 0})
	parent := filepath.Dir(g.DossierModeles())
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return EtatOutil{}, err
	}
	travail, err := os.MkdirTemp(parent, ".modeles-")
	if err != nil {
		return EtatOutil{}, err
	}
	defer os.RemoveAll(travail)
	tous := append(append([]Modele{}, ModelesNuclei...), LicenceModeles)
	for i, m := range tous {
		if !filepath.IsLocal(filepath.FromSlash(m.Chemin)) {
			return EtatOutil{}, fmt.Errorf("chemin de modèle refusé : %s", m.Chemin)
		}
		tmp, err := g.telecharger(ctx, "modele-"+m.ID, baseModeles+m.Chemin, m.SHA256, 2<<20)
		if err != nil {
			return EtatOutil{}, err
		}
		cible := filepath.Join(travail, filepath.FromSlash(m.Chemin))
		if err := os.MkdirAll(filepath.Dir(cible), 0o700); err == nil {
			err = os.Rename(tmp, cible)
		}
		if err != nil {
			_ = os.Remove(tmp)
			return EtatOutil{}, err
		}
		g.Progres(Etape{"nuclei-modeles", "Modèle vérifié : " + m.ID, (i + 1) * 100 / len(tous)})
	}
	final := g.DossierModeles()
	if err := os.RemoveAll(final); err != nil {
		return EtatOutil{}, err
	}
	if err := os.Rename(travail, final); err != nil {
		return EtatOutil{}, err
	}
	if err := g.verifierModeles(); err != nil {
		return EtatOutil{}, err
	}
	return g.etatModeles("installés et vérifiés"), nil
}

// verifierModeles : chaque modèle de la liste blanche est présent avec l'empreinte attendue, et le
// dossier ne contient AUCUN autre modèle (un fichier ajouté serait exécuté par Nuclei).
func (g *Gestionnaire) verifierModeles() error {
	racine := g.DossierModeles()
	attendus := map[string]string{}
	for _, m := range append(append([]Modele{}, ModelesNuclei...), LicenceModeles) {
		attendus[filepath.Clean(filepath.FromSlash(m.Chemin))] = m.SHA256
	}
	vus := 0
	err := filepath.WalkDir(racine, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("lien refusé dans les modèles : %s", p)
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(racine, p)
		sha, ok := attendus[rel]
		if !ok {
			return fmt.Errorf("fichier inattendu dans les modèles : %s", rel)
		}
		got, err := empreinteFichier(p)
		if err != nil {
			return err
		}
		if got != sha {
			return fmt.Errorf("modèle altéré : %s", rel)
		}
		vus++
		return nil
	})
	if err != nil {
		return err
	}
	if vus != len(attendus) {
		return fmt.Errorf("modèles incomplets (%d/%d)", vus, len(attendus))
	}
	return nil
}

func (g *Gestionnaire) etatModeles(detail string) EtatOutil {
	return EtatOutil{Nom: "nuclei-modeles", Version: VersionModeles, Licence: "MIT", Source: baseModeles,
		Chemin: g.DossierModeles(), Pret: true, Detail: fmt.Sprintf("%s — %d modèles en liste blanche", detail, len(ModelesNuclei))}
}

func empreinteFichier(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ----------------------------------------------------------------------------- exécution vérifiée

// Executable : binaire VÉRIFIÉ, verrouillé en écriture jusqu'à Fermer().
type Executable struct {
	Outil      Outil
	Chemin     string
	SHA256     string
	Signataire string
	f          *os.File
	env        []string
}

// Preparer contrôle un outil géré juste avant son exécution : empreinte du binaire (lu au travers
// d'un descripteur qui en interdit la modification) puis signature Authenticode si l'éditeur signe.
func (g *Gestionnaire) Preparer(o Outil) (*Executable, error) {
	var principal *Fichier
	for i := range o.Fichiers {
		if o.Fichiers[i].Dest == o.Executable {
			principal = &o.Fichiers[i]
		}
	}
	if principal == nil {
		return nil, fmt.Errorf("manifeste incomplet pour %s", o.Nom)
	}
	chemin := filepath.Join(g.Dossier(o), o.Executable)
	x, err := preparerChemin(o, chemin, principal.SHA256)
	if err != nil {
		return nil, err
	}
	if o.Nom == Nuclei.Nom {
		x.env = g.environnementNuclei()
	}
	return x, nil
}

func preparerChemin(o Outil, chemin, sha string) (*Executable, error) {
	f, err := ouvrirVerrouille(chemin)
	if err != nil {
		return nil, fmt.Errorf("%s %s non installé (%v)", o.Nom, o.Version, err)
	}
	x := &Executable{Outil: o, Chemin: chemin, f: f}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<62)); err != nil {
		x.Fermer()
		return nil, err
	}
	x.SHA256 = hex.EncodeToString(h.Sum(nil))
	if sha != "" && x.SHA256 != sha {
		x.Fermer()
		return nil, fmt.Errorf("%s : empreinte du binaire NON CONFORME — exécution refusée", o.Nom)
	}
	if len(o.Signataires) > 0 {
		if err := verifierAuthenticode(f); err != nil {
			x.Fermer()
			return nil, err
		}
		org, err := OrganisationSignataire(f)
		if err != nil || !signataireAdmis(org, o.Signataires) {
			x.Fermer()
			return nil, fmt.Errorf("%s : signataire %q non reconnu — exécution refusée", o.Nom, org)
		}
		x.Signataire = org
	}
	return x, nil
}

// environnementNuclei : configuration et cache de Nuclei confinés au dossier géré (aucune écriture
// dans le profil de l'utilisateur, aucun téléchargement de modèles publics).
func (g *Gestionnaire) environnementNuclei() []string {
	base := filepath.Join(g.Racine, "nuclei-config")
	_ = os.MkdirAll(base, 0o700)
	env := []string{}
	for _, v := range os.Environ() {
		k := strings.ToUpper(strings.SplitN(v, "=", 2)[0])
		if k == "APPDATA" || k == "LOCALAPPDATA" || k == "USERPROFILE" || k == "HOME" || k == "XDG_CONFIG_HOME" {
			continue
		}
		env = append(env, v)
	}
	return append(env, "APPDATA="+base, "LOCALAPPDATA="+base, "USERPROFILE="+base, "HOME="+base,
		"XDG_CONFIG_HOME="+base, "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true")
}

// Commande prépare l'exécution du binaire vérifié (arguments fournis par le code appelant, jamais
// par une saisie libre).
func (x *Executable) Commande(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, x.Chemin, args...)
	if x.env != nil {
		c.Env = x.env
	}
	c.Dir = filepath.Dir(x.Chemin)
	return c
}

// Fermer libère le verrou d'écriture (après la fin du processus).
func (x *Executable) Fermer() {
	if x != nil && x.f != nil {
		_ = x.f.Close()
		x.f = nil
	}
}

// Etat décrit le composant vérifié.
func (x *Executable) Etat(detail string) EtatOutil {
	return EtatOutil{Nom: x.Outil.Nom, Version: x.Outil.Version, Licence: x.Outil.Licence, Source: x.Outil.URL,
		Chemin: x.Chemin, SHA256: x.SHA256, Signataire: x.Signataire, Pret: true, Detail: detail}
}

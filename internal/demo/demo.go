// Package demo fournit le jeu d'observations du mode --demo (« Usine de Brest », entreprise
// fictive). Seul le RÉSEAU est simulé : l'appairage, le mTLS, les requêtes signées, le journal
// et l'envoi au serveur sont réels. Le jeu ne contient que des observations brutes, jamais
// de constat : l'analyse reste faite par le serveur, exactement comme pour un scan réel.
package demo

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"cacyber/agent/internal/scan"
)

//go:embed brest.json
var brut []byte

// Les dates relatives « @jours:-N » sont résolues à l'exécution (aujourd'hui − N jours), pour
// que l'ancienneté des correctifs et des sauvegardes reste stable quel que soit le jour de la démo.
var rxJours = regexp.MustCompile(`^@jours:(-?\d+)$`)

func resoudre(v any, aujourdhui time.Time) any {
	switch x := v.(type) {
	case map[string]any:
		res := map[string]any{}
		for k, val := range x {
			if len(k) > 0 && k[0] == '_' { // commentaires du fichier
				continue
			}
			res[k] = resoudre(val, aujourdhui)
		}
		return res
	case []any:
		for i := range x {
			x[i] = resoudre(x[i], aujourdhui)
		}
		return x
	case string:
		if m := rxJours.FindStringSubmatch(x); m != nil {
			n, _ := strconv.Atoi(m[1])
			return aujourdhui.AddDate(0, 0, n).Format("2006-01-02")
		}
	}
	return v
}

// Observations renvoie les observations de démonstration, dates résolues par rapport à `aujourdhui`.
func Observations(aujourdhui time.Time) (scan.Observations, error) {
	var generique any
	if err := json.Unmarshal(brut, &generique); err != nil {
		return scan.Observations{}, fmt.Errorf("jeu de démonstration illisible : %w", err)
	}
	resolu, _ := json.Marshal(resoudre(generique, aujourdhui))
	var o scan.Observations
	if err := json.Unmarshal(resolu, &o); err != nil {
		return scan.Observations{}, fmt.Errorf("jeu de démonstration incompatible : %w", err)
	}
	o.Mode = "demo"
	return o, nil
}

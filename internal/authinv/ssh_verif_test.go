package authinv

import (
	"context"
	"strings"
	"testing"
	"time"

	"cacyber/agent/internal/identifiants"
)

// Sans known_hosts ni acceptation explicite, l'inventaire SSH est refusé AVANT toute connexion :
// le mot de passe n'est jamais envoyé à un hôte non authentifié.
func TestSSHRefuseSansVerificationDeCle(t *testing.T) {
	id := &identifiants.Identifiants{Utilisateur: "audit"}
	_, err := inventaireSSH(context.Background(), "127.0.0.1", Options{Linux: id, Delai: time.Second})
	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Fatalf("refus attendu sans known_hosts, obtenu : %v", err)
	}
}

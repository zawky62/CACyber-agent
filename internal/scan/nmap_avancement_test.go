package scan

import "testing"

// Les lignes <taskprogress> de Nmap donnent l'étape, un pourcentage global et le temps restant.
func TestLireAvancementNmap(t *testing.T) {
	a, ok := lireAvancement(`<taskprogress task="Connect Scan" time="1762444800" percent="50.00" remaining="120" etc="1762444920"/>`)
	if !ok || a.Etape != "examen des ports" || a.Pourcentage != 40 || a.RestantSecs != 120 {
		t.Fatalf("avancement inattendu : %+v %v", a, ok)
	}
	if _, ok := lireAvancement(`<host><status state="up"/></host>`); ok {
		t.Fatal("une ligne d'hôte n'est pas une progression")
	}
	b, _ := lireAvancement(`<taskprogress task="NSE" time="1" percent="100.00"/>`)
	if b.Pourcentage != 100 || b.RestantSecs != 0 {
		t.Fatalf("NSE terminé attendu à 100 %% : %+v", b)
	}
}

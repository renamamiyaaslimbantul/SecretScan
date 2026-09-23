package entropy

import "testing"

func TestShannon(t *testing.T) {
	if got := Shannon(""); got != 0 {
		t.Fatalf("empty entropy = %v", got)
	}
	if got := Shannon("aaaaaaaa"); got != 0 {
		t.Fatalf("repeated entropy = %v", got)
	}
	if got := Shannon("aB3$xY9!"); got < 2.5 {
		t.Fatalf("diverse entropy too low: %v", got)
	}
}

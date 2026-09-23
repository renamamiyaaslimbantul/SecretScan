package filters

import "testing"

func TestRejectsObviousExamples(t *testing.T) {
	f := New(nil)
	for _, value := range []string{"YOUR_API_KEY_HERE", "example-token", "test-password", "<your-token>", "changeme"} {
		if !f.IsFalsePositive(value, "API_KEY = \""+value+"\"") {
			t.Errorf("expected %q filtered", value)
		}
	}
	if f.IsFalsePositive("z9Qp2Lm7Vx4Nc8Rt", "api_key = \"z9Qp2Lm7Vx4Nc8Rt\"") {
		t.Fatal("real-looking value filtered")
	}
}

func TestConfiguredExclusion(t *testing.T) {
	f, err := Compile([]string{`^SAFE_[A-Z]+$`})
	if err != nil {
		t.Fatal(err)
	}
	if !f.IsFalsePositive("SAFE_VALUE", "token=SAFE_VALUE") {
		t.Fatal("configured exclusion ignored")
	}
}

package selfupdate

import "testing"

func TestManagedProfileRefusesSelfUpdate(t *testing.T) {
	t.Setenv(ProfileEnv, "managed")
	if ok, why := Allowed(); ok || why == "" {
		t.Fatalf("managed fleet allowed a self-update (ok=%v, reason=%q)", ok, why)
	}
	for _, p := range []string{"", "cloud", "vpc", "selfhost"} {
		t.Setenv(ProfileEnv, p)
		if ok, why := Allowed(); !ok || why != "" {
			t.Fatalf("profile %q refused a self-update: %q — only managed is off by default", p, why)
		}
	}
}

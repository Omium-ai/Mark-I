package anchors

import "testing"

// TestGrantRefused (M8): the AppContainer grant rule on Windows-shaped paths, run on every OS.
func TestGrantRefused(t *testing.T) {
	protected := []string{`C:\Users\me`, `C:\Users\me\AppData\Local`, `C:\Users\me\AppData\Roaming`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`, `C:\Windows`, ""}
	poisoned := []string{`C:\Users\me\AppData\Local\Programs`, `C:\Users\me\AppData\Local\Microsoft\WindowsApps`}
	for dir, refused := range map[string]bool{
		`C:\Users\me`: true, `c:/users/ME/AppData/Local`: true, `C:\Users\me\`: true, `C:\Users`: true, `C:\`: true, `C:`: true, `c:/`: true,
		`D:\`: true, `\\server\share`: true, `\\server\share\`: true, `\\server`: true, `\\?\C:\`: true, `\\?\UNC\server\share`: true,
		`C:\Program Files`: true, `C:\Windows`: true, `C:\ProgramData`: true, `C:\Users\me\AppData`: true, `relative\dir`: true, ``: true,
		`C:\Users\me\AppData\Local\Programs`: true, `C:\Users\me\AppData\Local\Programs\Mark 1\resources`: true, `c:/users/me/appdata/local/microsoft/windowsapps/x`: true,
		`C:\Users\me\repo`: false, `C:\Users\me\repo\.git`: false, `c:/users/me/src/r/.git/worktrees/wt`: false, `C:\Users\me\AppData\Local\Temp\mark1`: false,
		`C:\Program Files\Git`: false, `D:\work\repo`: false, `\\server\share\repo`: false, `\\?\C:\Users\me\repo`: false, `C:\Users\meow`: false,
	} {
		if got := grantRefused(dir, protected, poisoned); (got != "") != refused {
			t.Errorf("grantRefused(%q) = %q, want refused=%v", dir, got, refused)
		}
	}
}

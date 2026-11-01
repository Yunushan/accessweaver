package nativeargs

import "testing"

func TestByeDPIInstallContract(t *testing.T) {
	for _, args := range [][]string{
		{"--i=0.0.0.0"}, {"--ip", "127.0.0.1"}, {"--po=9999"}, {"--port=1080"},
		{"--dae"}, {"--daemonize"}, {"--s"}, {"--service"}, {"--trans"}, {"-Ui0.0.0.0"},
		{"-i0.0.0.0"}, {"-p", "9999"}, {"-D"}, {"-E"}, {"--"}, {"--=value"}, {"@options.txt"},
	} {
		if ValidateByeDPIInstall(args) == nil {
			t.Errorf("reserved argument accepted: %q", args)
		}
	}
	for _, args := range [][]string{nil, {"--split", "2"}, {"--disorder"}, {"--comment", ""}, {"--split=2", "--comment", "ordinary text"}} {
		if err := ValidateByeDPIInstall(args); err != nil {
			t.Errorf("strategy rejected: %q: %v", args, err)
		}
	}
}

func TestExactOptionPrecedesLongerOptionPrefix(t *testing.T) {
	options := []string{"--daemon", "--daemonize", "--ip"}
	if Abbreviates("--daemon", options...) || Abbreviates("--ip=127.0.0.1", options...) {
		t.Fatal("exact protected name treated as abbreviation")
	}
	if !Abbreviates("--dae", options...) || !Abbreviates("--i=0.0.0.0", options...) {
		t.Fatal("protected prefix not recognized")
	}
	if Abbreviates("--ip-extra", options...) || Abbreviates("--", options...) {
		t.Fatal("unrelated option treated as prefix")
	}
}

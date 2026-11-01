package nativepath

import "strings"

// Remove command/module/runtime injection variables before setting OS-derived
// locations. Keep desktop-user identity variables needed by application tools.
func cleanEnvironment(original, overrides []string) []string {
	blocked := map[string]bool{"PATH": true, "PROGRAMFILES": true, "PROGRAMFILES(X86)": true, "PROGRAMW6432": true, "COMMONPROGRAMFILES": true, "COMMONPROGRAMFILES(X86)": true, "COMMONPROGRAMW6432": true, "DEVPATH": true, "APPDOMAIN_MANAGER_ASM": true, "APPDOMAIN_MANAGER_TYPE": true, "__COMPAT_LAYER": true, "SYSTEMROOT": true, "WINDIR": true, "PROGRAMDATA": true, "ALLUSERSPROFILE": true, "SYSTEMDRIVE": true, "COMSPEC": true, "PSMODULEPATH": true, "PSEXECUTIONPOLICYPREFERENCE": true,
		"LUA_PATH": true, "LUA_CPATH": true, "NODE_OPTIONS": true, "NODE_PATH": true, "PYTHONPATH": true, "PYTHONHOME": true, "RUBYOPT": true, "PERL5OPT": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true}
	result := make([]string, 0, len(original)+len(overrides))
	for _, item := range original {
		name, _, ok := strings.Cut(item, "=")
		if !ok || name == "" {
			continue
		}
		name = strings.ToUpper(name)
		if blocked[name] || strings.HasPrefix(name, "CORECLR_") || strings.HasPrefix(name, "LUA_") || strings.HasPrefix(name, "PYTHON") || strings.HasPrefix(name, "COR_") || strings.HasPrefix(name, "COMPLUS_") || strings.HasPrefix(name, "DOTNET_") || strings.HasPrefix(name, "DYLD_") {
			continue
		}
		result = append(result, item)
	}
	return append(result, overrides...)
}

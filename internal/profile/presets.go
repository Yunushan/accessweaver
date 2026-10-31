package profile

// Builtins are editable strategy starting points, not promises about any ISP.
// Engines and credentials are supplied by the user. No preset runs on startup.
func Builtins() []Profile {
	byedpi := New("discord-proxy", "Discord · selective SOCKS", "byedpi")
	byedpi.Category = "Starting point"
	byedpi.Description = "A loopback ByeDPI proxy with a simple split strategy, limited to the listed Discord domains. Configure the target application's SOCKS5 proxy separately."
	byedpi.Args = []string{"--ip", "127.0.0.1", "--port", "1080", "--split", "2"}
	byedpi.Routing.IncludeDomains = []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"}
	byedpi.Notes = "SOCKS5 endpoint: 127.0.0.1:1080. Use proxy DNS if the application supports it. A successful direct diagnostic does not test this SOCKS route. The split strategy is an editable example, not a tested recommendation for your ISP."

	local := New("byedpi-exclusions", "ByeDPI · exclusion workspace", "byedpi")
	local.Category = "Advanced"
	local.Description = "Apply an editable split strategy to traffic sent to this proxy, except domains in the exclusion list. Excluded traffic still uses the local proxy without manipulation."
	local.Args = []string{"--ip", "127.0.0.1", "--port", "1081", "--split", "2"}
	local.Routing.ExcludeDomains = []string{"microsoft.com", "windowsupdate.com"}
	local.Notes = "SOCKS5 endpoint: 127.0.0.1:1081. Add domains that need unmodified traffic. Guided lists generate ordered ByeDPI groups; clear the lists before authoring your own --auto/--hosts groups."

	z2 := New("zapret2-custom", "zapret2 · strategy workspace", "zapret2")
	z2.Category = "Advanced"
	z2.Description = "Bring a trusted winws2/nfqws2/dvtws2 binary, upstream Lua assets and a tested native strategy. Interception setup depends on the operating system."
	z2.Routing.ExcludeDomains = []string{"windowsupdate.com", "microsoft.com"}
	z2.Notes = "Setup template: add --lua-init asset paths, --lua-desync strategy options, and the correct capture/queue options for your OS. Preview reports the missing strategy. Generated exclusions are applied to every --new section. No macOS support upstream."

	legacy := New("zapret-legacy", "zapret · legacy workspace", "zapret")
	legacy.Category = "Legacy"
	legacy.Description = "Preserve an existing tested zapret 1 strategy. The upstream is end-of-life; platform capture setup and native arguments are explicit."
	legacy.Notes = "Choose winws on Windows; nfqws or tpws on Linux; dvtws or tpws on BSD. macOS supports only tpws SOCKS mode here: --socks --bind-addr=127.0.0.1 --port=1082 --split-pos=2. Use an absolute binary path to choose the variant."

	gd := New("goodbyedpi-selective", "GoodbyeDPI · selective Windows", "goodbyedpi")
	gd.Category = "Windows"
	gd.Description = "Windows packet processing restricted by HTTP Host/TLS SNI includes. Uses the upstream -5 example mode; effectiveness must be tested locally."
	gd.Args = []string{"-5"}
	gd.Routing.IncludeDomains = []string{"discord.com", "discord.gg"}
	gd.Notes = "Requires official WinDivert files and administrator rights. Includes map to --blacklist. General domain exclusions and per-application routing are not supported by this adapter."

	ws := New("wiresock-custom", "WireSock · private tunnel", "wiresock")
	ws.Category = "Windows"
	ws.Description = "Manage the vendor's foreground WireSock SDK client using your existing WireGuard .conf file. Set configPath and install WireSock separately under its license."
	ws.Notes = "AllowedApps, DisallowedApps and IP routing belong in the external .conf file. Do not paste private keys in profile notes. Config command hooks are rejected. This manager never provisions VPN credentials or installs services."

	sp := New("spoofdpi-local", "SpoofDPI · local HTTP proxy", "spoofdpi")
	sp.Category = "Optional"
	sp.Description = "Run a user-installed SpoofDPI build with its native options. Review the version's listen and system-proxy flags before starting."
	sp.Notes = "Some SpoofDPI versions change macOS system proxy settings by default. Explicitly configure that behavior in native arguments; the controller cannot restore changes made by third-party software."

	sing := New("sing-box-custom", "sing-box · configuration workspace", "sing-box")
	sing.Category = "Optional"
	sing.Description = "Run an existing local sing-box configuration. Set configPath to the absolute JSON path; review all DNS, routing, listener and optional TUN settings."
	sing.Notes = "The adapter supplies run -c and configPath. Additional args are passed literally. Credentials and routing stay in your external config, which is not exported with this profile."

	xray := New("xray-custom", "Xray · configuration workspace", "xray")
	xray.Category = "Optional"
	xray.Description = "Run Xray-core with an existing local configuration and any authorized upstream endpoints. Set an absolute configPath."
	xray.Notes = "The adapter supplies run -config and configPath. Remote configuration URLs are rejected. Credentials stay in the external configuration, which is not included in profile exports."
	return []Profile{byedpi, local, z2, legacy, gd, ws, sp, sing, xray}
}

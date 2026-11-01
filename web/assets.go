package web

import "embed"

//go:embed index.html app.css app.js system.js locales.js
var Assets embed.FS

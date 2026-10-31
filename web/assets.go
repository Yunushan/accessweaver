package web

import "embed"

//go:embed index.html app.css app.js
var Assets embed.FS

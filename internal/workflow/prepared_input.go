package workflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Yunushan/accessweaver/internal/buildinfo"
	"github.com/Yunushan/accessweaver/internal/managed"
	"github.com/Yunushan/accessweaver/internal/nativepath"
)

type preparedWorkflowInput struct {
	Script, Input             []byte
	ResultPath, ResultToken   string
	RequestSHA256             string
	ScriptSHA256, InputSHA256 string
	Authorization             *managed.Authorization
}
type preparedWorkflowInputKey struct{}

// Preparation reads no editable request snapshot. The same retained bytes are
// reserved, privately staged, and embedded in the actual stdin program.
func prepareWorkflowInput(dir string, r Request, permission managed.WorkflowPermission) (*preparedWorkflowInput, error) {
	script, err := scripts.ReadFile("windows.ps1")
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	hook, err := presetFiles.ReadFile("presets/00-accessweaver-isp.sh")
	if err != nil {
		return nil, err
	}
	architecture, _ := nativepath.WindowsArchitecture()
	token := make([]byte, 24)
	if _, err = rand.Read(token); err != nil {
		return nil, err
	}
	p := &preparedWorkflowInput{Authorization: permission.Authorization, Script: script, ResultPath: filepath.Join(dir, "result.json"), ResultToken: hex.EncodeToString(token)}
	requestBytes, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	p.RequestSHA256 = workflowLifecycleHash(requestBytes)
	var controllerBuild *buildinfo.Info
	if r.Action == "updates" {
		build := buildinfo.Current()
		controllerBuild = &build
	}
	p.Input, err = json.Marshal(struct {
		NativeArchitecture string                 `json:"nativeArchitecture"`
		Request            Request                `json:"request"`
		Controller         string                 `json:"controller"`
		ControllerBuild    *buildinfo.Info        `json:"controllerBuild,omitempty"`
		ResultPath         string                 `json:"resultPath"`
		ResultToken        string                 `json:"resultToken"`
		ISPHook            string                 `json:"ispHook"`
		ManagedPolicy      bool                   `json:"managedPolicy"`
		AllowDownloads     bool                   `json:"allowDownloads"`
		Downloads          []managed.DownloadRule `json:"downloads"`
	}{architecture, r, executable, controllerBuild, p.ResultPath, p.ResultToken, string(hook), permission.Managed, permission.AllowDownloads, permission.Downloads})
	if err != nil {
		return nil, err
	}
	p.ScriptSHA256 = workflowLifecycleHash(p.Script)
	p.InputSHA256 = workflowLifecycleHash(p.Input)
	return p, nil
}
func preparedWorkflowFrom(ctx context.Context) *preparedWorkflowInput {
	p, _ := ctx.Value(preparedWorkflowInputKey{}).(*preparedWorkflowInput)
	return p
}

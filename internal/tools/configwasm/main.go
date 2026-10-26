//go:build js && wasm

// Command configwasm is the browser side of the documentation config builder.
// It exposes config.Diagnose to JavaScript as globalThis.ranCheck(envJSON), so
// the builder checks a configuration with the same code the sensor runs at
// startup. Build it with docs/scripts/build-wasm.mjs.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/st0o0/ran/internal/config"
)

func check(_ js.Value, args []js.Value) any {
	d := config.Diagnosis{Error: "ranCheck needs one JSON argument", Warnings: []string{}}
	if len(args) == 1 {
		env := map[string]string{}
		if err := json.Unmarshal([]byte(args[0].String()), &env); err != nil {
			d.Error = "ranCheck: " + err.Error()
		} else {
			// A fixture file path cannot be read in the browser.
			delete(env, "RAN_HTTP_FIXTURES")
			d = config.Diagnose(func(k string) string { return env[k] })
		}
	}
	out, err := json.Marshal(d)
	if err != nil {
		return `{"error":"ranCheck: encode failed","warnings":[]}`
	}
	return string(out)
}

func main() {
	js.Global().Set("ranCheck", js.FuncOf(check))
	select {} // keep the runtime alive for calls from JavaScript
}

//go:build js && wasm
// +build js,wasm

package wasm

import (
	"syscall/js"

	"github.com/handsomecheung/mb64"
)

// RegisterWasmFunctions registers the mb64 encoding/decoding functions to the global JavaScript object
func RegisterWasmFunctions() {
	js.Global().Set("mb64", map[string]interface{}{
		"setFontSize": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				return js.ValueOf("error: expected 1 argument")
			}

			mb64.Bypass()

			return nil
		}),
		"setFont": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				return js.ValueOf("error: expected 1 argument")
			}

			input := args[0].String()
			err := mb64.SetEncoding(input)
			if err != nil {
				return js.ValueOf("error: " + err.Error())
			}

			return nil
		}),

		"renderIn": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				return js.ValueOf("error: expected 1 argument")
			}

			// Convert JavaScript Uint8Array to Go []byte
			input := make([]byte, args[0].Get("length").Int())
			js.CopyBytesToGo(input, args[0])

			encoded, err := mb64.Encode(input)
			if err != nil {
				return js.ValueOf("error: " + err.Error())
			}
			return js.ValueOf(string(encoded))
		}),

		"renderOut": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				return js.ValueOf("error: expected 1 argument")
			}

			input := args[0].String()
			decoded, err := mb64.Decode([]byte(input))
			if err != nil {
				return js.ValueOf("error: " + err.Error())
			}

			// Create JavaScript Uint8Array and copy decoded data
			result := js.Global().Get("Uint8Array").New(len(decoded))
			js.CopyBytesToJS(result, decoded)
			return result
		}),
	})
}

//go:build js && wasm
// +build js,wasm

package main

import (
	"github.com/handsomecheung/mb64/internal/wasm"
)

func main() {
	wasm.RegisterWasmFunctions()

	// Keep the program running
	select {}
}

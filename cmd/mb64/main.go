package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/handsomecheung/mb64"
)

func main() {
	keyFlag := flag.String("key", "", "The key for encoding/decoding")
	outputFile := flag.String("output", "", "Output file path (optional, defaults to stdout)")
	flag.Parse()

	actualKey := *keyFlag
	if actualKey == "" {
		actualKey = os.Getenv("MB_KEY")
	}

	if actualKey == "" {
		fmt.Fprintln(os.Stderr, "Error: --key flag or MB_KEY environment variable is required")
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: mb64 --key <key> [encrypt|decrypt] [content] --output <file>")
		os.Exit(1)
	}

	command := args[0]
	var content []byte
	var err error

	if len(args) > 1 {
		content = []byte(args[1])
	} else {
		content, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	mb64.SetEncoding(actualKey)

	var result []byte

	switch command {
	case "encrypt":
		result, err = mb64.Encode(content)
	case "decrypt":
		result, err = mb64.Decode(content)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command '%s'. Must be 'encrypt' or 'decrypt'.\n", command)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during %s: %v\n", command, err)
		os.Exit(1)
	}

	if *outputFile != "" {
		err := os.WriteFile(*outputFile, result, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file '%s': %v\n", *outputFile, err)
			os.Exit(1)
		}
		fmt.Printf("Successfully wrote output to %s\n", *outputFile)
	} else {
		fmt.Print(string(result))
	}
}

// Command fwknop-convert converts legacy C fwknop configuration files to
// the YAML format used by the Go fwknop implementation.
//
// Supported conversions:
//
//	fwknop-convert --type client --input ~/.fwknoprc
//	fwknop-convert --type server --input /etc/fwknop/fwknopd.conf
//	fwknop-convert --type access --input /etc/fwknop/access.conf
package main

import (
	"fmt"
	"os"

	"github.com/damienstuart/fwknop-go/internal/buildinfo"
	"github.com/spf13/pflag"
)

var version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fwknop-convert: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	f := pflag.NewFlagSet("fwknop-convert", pflag.ContinueOnError)
	f.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: fwknop-convert --type <client|server|access> --input <file>\n\nOptions:\n")
		f.PrintDefaults()
	}

	convType := f.StringP("type", "t", "", "Conversion type: client, server, or access")
	input := f.StringP("input", "i", "", "Input file path")
	help := f.BoolP("help", "h", false, "Print usage")
	showVersion := f.BoolP("version", "V", false, "Print version")

	if err := f.Parse(args); err != nil {
		return err
	}

	if *help {
		f.Usage()
		return nil
	}

	if *showVersion {
		bi := buildinfo.GetInfo(version)
		fmt.Printf("fwknop-convert version %s\n", bi)
		return nil
	}

	if *input == "" {
		f.Usage()
		return fmt.Errorf("--input is required")
	}

	switch *convType {
	case "client":
		return convertClient(*input)
	case "server":
		return convertServer(*input)
	case "access":
		return convertAccess(*input)
	default:
		f.Usage()
		return fmt.Errorf("--type must be client, server, or access")
	}
}

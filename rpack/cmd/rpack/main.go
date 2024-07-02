package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/pyke369/golang-support/rpack"
)

func main() {
	var (
		options flag.FlagSet
		usemain bool
	)

	options = flag.FlagSet{Usage: func() {
		os.Stderr.WriteString("usage: " + filepath.Base(os.Args[0]) + " [options] <rootdir>\n\noptions are:\n\n")
		options.PrintDefaults()
	},
	}
	options.String("output", "resources.go", "the generated output file path")
	options.String("pkgname", "main", "the package name to use in the generated output")
	options.String("funcname", "Resources", "the function name prefix to use in the generated output")
	options.String("default", "index.html", "the document to act as default")
	options.String("exclude", "", "an optionnal pattern of paths to exclude")
	options.Bool("main", false, "whether to generate a main func or not")
	if err := options.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	if options.NArg() == 0 {
		options.Usage()
		os.Exit(1)
	}
	if options.Lookup("main").Value.String() == "true" {
		usemain = true
	}
	rpack.Pack(options.Arg(0), options.Lookup("output").Value.String(), options.Lookup("pkgname").Value.String(),
		options.Lookup("funcname").Value.String(), options.Lookup("default").Value.String(),
		options.Lookup("exclude").Value.String(), usemain)
}

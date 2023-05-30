package main

import (
	"fmt"
	"os"

	_ "github.com/pyke369/golang-support/mstore"
)

func usage(status int) {
	fmt.Fprintf(os.Stderr, "usage: mstore <action> [parameters...]\n\n"+
		"help                             show this help screen\n"+
		"info   <store> <metric>          ...\n"+
		"export <store> <metric>          ...\n"+
		"import <store> <metric> <data>   ...\n")
	os.Exit(status)
}

func main() {
	if len(os.Args) < 2 {
		usage(1)
	}
	switch os.Args[1] {
	case "help":
		usage(0)
	case "info":
	case "export":
	case "import":
	default:
		usage(2)
	}
}

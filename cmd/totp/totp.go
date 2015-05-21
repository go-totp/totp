package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"text/tabwriter"

	"gopkg.in/totp.v0"
)

var (
	qrcode = flag.Bool("qrcode", false, "Generate the QrCode in /tmp")
	output = flag.String("output", "/tmp", "The folder in which to generate the QRcode images")
)

func main() {
	flag.Parse()

	var sources []*totp.Source

	// Read the JSON config file.
	sourceFile, err := os.Open(path.Join(os.Getenv("HOME"), ".totprc"))
	if err != nil {
		log.Fatal(err)
	}
	sourceParser := json.NewDecoder(sourceFile)
	if err = sourceParser.Decode(&sources); err != nil {
		log.Fatal(err)
	}

	// Init the tabwriter.
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)

	// Iterate over the sources and print them all to the writer.
	for _, s := range sources {
		if err := s.Valid(); err != nil {
			fmt.Println("Source is invalid: %s", err)
			os.Exit(1)
		}

		if *qrcode {
			qrcode, err := s.Qrcode()
			if err != nil {
				log.Printf("Error generating the qrcode: %s", err)
			} else {
				ioutil.WriteFile(fmt.Sprintf("%s/%s.png", *output, s.Name), qrcode, 0644)
			}
		}

		fmt.Fprintf(w, "%s\t=> %s\n", s.Name, s.Totp())
	}

	// Flush the writer.
	w.Flush()
}

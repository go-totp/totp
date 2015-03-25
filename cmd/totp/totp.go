package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"text/tabwriter"

	"gopkg.in/totp.v0"
)

func main() {
	var sources []*totp.TotpSource

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
		if s.Secret == "" {
			fmt.Println("Secret is required. %q has no secret defined", s.Name)
			os.Exit(1)
		}

		qrcode, err := s.Qrcode()
		if err != nil {
			log.Printf("Error generating the qrcode: %s", err)
		} else {
			ioutil.WriteFile(fmt.Sprintf("/tmp/%s.png", s.Name), qrcode, 0644)
		}

		fmt.Fprintf(w, "%s\t=> %s\n", s.Name, s.Totp())
	}

	// Flush the writer.
	w.Flush()
}

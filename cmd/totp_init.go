package cmd

import (
	"encoding/json"
	"log"
	"os"

	"gopkg.in/totp.v0"
)

func newTotp() *totp.Totp {
	sourceFile, err := os.Open(cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	var sources []*totp.Source
	if err := json.NewDecoder(sourceFile).Decode(&sources); err != nil {
		log.Fatal(err)
	}
	t := &totp.Totp{Sources: make(map[int]*totp.Source, len(sources))}
	for _, source := range sources {
		if err := source.Valid(); err != nil {
			log.Fatalf("Source is invalid: %s", err)
		}
		if t.Sources[source.ID] != nil {
			log.Fatalf("the ID %d already exists. Duplicate %v", source.ID, source)
		}
		t.Sources[source.ID] = source
	}

	return t
}

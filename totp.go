package totp

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Totp represents the main object holding the sources.
type Totp struct {
	Sources map[int]*Source
}

// List returns the list of sources encoded as json.
func (t *Totp) List(w http.ResponseWriter, r *http.Request) {
	sources := make([]*Source, 0, len(t.Sources))
	for _, source := range t.Sources {
		sources = append(sources, source)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sources); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Code returns the code of a source
func (t *Totp) Code(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get(":id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if t.Sources[id] == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
	code := struct {
		Code string `json:"code"`
	}{
		Code: t.Sources[id].Code(),
	}

	if err := json.NewEncoder(w).Encode(code); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

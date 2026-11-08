// Command practice-target runs a deliberately vulnerable local web app used
// ONLY as a practice target for E2E tests and demos. It must never be shipped
// or exposed beyond localhost.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/iwiels/ARGOS/argos-bin/internal/practicetarget"
)

func main() {
	host := flag.String("host", "127.0.0.1", "listen host")
	port := flag.Int("port", 8787, "listen port")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Practice target (intentionally vulnerable) on http://%s", addr)
	log.Printf("LOCAL TESTING ONLY — do not expose this beyond localhost")
	if err := http.ListenAndServe(addr, practicetarget.Handler()); err != nil {
		log.Fatal(err)
	}
}

// Command a2a-testagent runs the local A2A v1.0 test agent used by the
// gateway's development and S-A2A-1 lifecycle tests.
package main

import (
	"flag"
	"log"
	"net/http"

	"security-ai-gateway/gateway/a2a/testagent"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9001", "listen address")
	publicURL := flag.String("public-url", "", "gateway-form card URL (default http://<addr>/a2a)")
	tenant := flag.String("tenant", "", "optional interface tenant")
	flag.Parse()

	cardURL := *publicURL
	if cardURL == "" {
		cardURL = "http://" + *addr + "/a2a"
	}
	agent, err := testagent.New(testagent.Config{
		PublicURL: cardURL,
		Tenant:    *tenant,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("A2A test agent listening on %s (card %s, endpoint %s)", *addr, cardURL, cardURL)
	log.Fatal(http.ListenAndServe(*addr, agent.Handler()))
}

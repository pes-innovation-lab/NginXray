package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/elastic/go-elasticsearch/v9"
)

var Client *elasticsearch.TypedClient

const esAddr = "http://localhost:9200"

const indexTemplateBody = `{
  "index_patterns": ["nginxray-http*"],
  "priority": 100,
  "template": {
    "mappings": {
      "properties": {
        "timestamp":   { "type": "date" },
        "pid":         { "type": "long" },
        "tid":         { "type": "long" },
        "direction":   { "type": "keyword" },
        "clientIP":    { "type": "ip" },
        "clientPort":  { "type": "integer" },
        "serverIP":    { "type": "ip" },
        "serverPort":  { "type": "integer" },
        "method":      { "type": "keyword" },
        "path":        { "type": "keyword" },
        "version":     { "type": "keyword" },
        "status":      { "type": "integer" },
        "body":        { "type": "text" }
      }
    }
  }
}`


func Init() {
	client, err := elasticsearch.NewTyped(
		elasticsearch.WithAddresses(esAddr),
	)
	if err != nil {
		log.Printf("warning: creating elasticsearch client: %v (event logging disabled)", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.Info().Do(ctx)
	if err != nil {
		log.Printf("warning: connecting to elasticsearch: %v (event logging disabled)", err)
		return
	}

	if err := ensureIndexTemplate(); err != nil {
		log.Printf("warning: could not create elasticsearch index template: %v", err)
	}

	Client = client
	log.Printf("Connected to Elasticsearch cluster %q\n", info.ClusterName)

	startWorker()
}

func ensureIndexTemplate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		esAddr+"/_index_template/nginxray-http-template",
		bytes.NewBufferString(indexTemplateBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

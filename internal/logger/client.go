package logging

import (
	"context"
	"log"

	"github.com/elastic/go-elasticsearch/v9"
)

var Client *elasticsearch.TypedClient

func Init() {
	client, err := elasticsearch.NewTyped(
		elasticsearch.WithAddresses("http://localhost:9200"),
	)
	if err != nil {
		log.Fatalf("creating elasticsearch client: %v", err)
	}

	Client = client

	info, err := Client.Info().Do(context.Background())
	if err != nil {
		log.Fatalf("connecting to elasticsearch: %v", err)
	}

	log.Printf("Connected to Elasticsearch cluster %q\n", info.ClusterName)
}


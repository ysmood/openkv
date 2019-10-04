package openkv

import (
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/ysmood/kit"
	"github.com/ysmood/storer/pkg/kvstore"
)

// ServerHandler ...
type ServerHandler func(http.ResponseWriter, *http.Request)

type txn struct {
	db       kvstore.Store
	upgrader *websocket.Upgrader
}

// Serve ...
func Serve(db kvstore.Store, upgrader *websocket.Upgrader) ServerHandler {
	t := txn{db, upgrader}

	return t.Handler
}

func (t *txn) Handler(w http.ResponseWriter, r *http.Request) {
	c, err := t.upgrader.Upgrade(w, r, nil)
	kit.E(err)
	defer c.Close()
}

func (t *txn) exec(c *websocket.Conn) {
	for {
		c.ReadMessage()
	}
}

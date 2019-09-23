package openkv

import (
	"github.com/ysmood/kit"
)

// Server ...
type Server struct {
}

func NewServer() *Server {
	kit.Log("ok")

	return &Server{}
}

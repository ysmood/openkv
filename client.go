package openkv

import (
	"bytes"

	"github.com/ysmood/byframe"
	"github.com/ysmood/kit"
	"github.com/ysmood/openkv/pkg/crypto"
)

type Client struct {
	host string
	key  *crypto.PrivateKey
}

func NewClient(host, keyFile string) *Client {
	file, err := kit.ReadFile(keyFile)
	kit.E(err)
	key, err := crypto.NewPrivateKey(file)
	kit.E(err)

	return &Client{
		host: host,
		key:  key,
	}
}

func (c *Client) SetBytes(key, value []byte) error {
	sig, err := c.key.Sign(append(key, value...))
	if err != nil {
		return err
	}

	data := byframe.EncodeTuple(&sig, &key, &value)

	buf := bytes.NewBuffer(data)

	return kit.Req(c.host).Post().Body(buf).Do()
}

package openkv

import (
	"bytes"
	"encoding/hex"

	"github.com/ysmood/byframe"
	"github.com/ysmood/kit"
	"github.com/ysmood/openkv/pkg/crypto"
)

// Client ...
type Client struct {
	host string
	key  *crypto.PrivateKey
}

// NewClient ...
func NewClient(host, keyFile string) *Client {
	file, err := kit.ReadFile(keyFile)
	kit.E(err)
	key, err := crypto.NewPrivateKey(file)
	kit.E(err)

	kit.Req(host).Post().StringBody(hex.EncodeToString(key.PublicHash())).Do()

	return &Client{
		host: host,
		key:  key,
	}
}

// SetBytes ...
func (c *Client) SetBytes(key, value []byte) error {
	sig, err := c.key.Sign(append(key, value...))
	if err != nil {
		return err
	}

	data := byframe.EncodeTuple(&sig, &key, &value)

	buf := bytes.NewBuffer(data)

	return kit.Req(c.host).Put().Body(buf).Do()
}

// GetBytes ...
func (c *Client) GetBytes(key []byte) ([]byte, error) {
	buf, err := kit.Req(c.host + "/" + hex.EncodeToString(key)).Bytes()
	if err != nil {
		return nil, err
	}

	var sig, value []byte
	byframe.DecodeTuple(buf, &sig, &value)

	err = c.key.Verify(append(key, value...), sig)
	if err != nil {
		return nil, err
	}

	return value, nil
}

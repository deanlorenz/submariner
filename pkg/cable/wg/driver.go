package wg

import (
	"errors"

	"github.com/submariner-io/submariner/pkg/types"
)

type wireguard struct {
	// TBD
}

// NewDriver creates a new Wireguard driver
func NewDriver(subnets []string, ep types.SubmarinerEndpoint) (*wireguard, error) {
	return &wireguard{}, errors.New("wip: wireguard not implemented")
}

func (w *wireguard) Init() error {
	return nil
}

func (w *wireguard) ConnectToEndpoint(ep types.SubmarinerEndpoint) (string, error) {
	return "", errors.New("wip: wireguard not implemented")
}

func (w *wireguard) DisconnectFromEndpoint(endpoint types.SubmarinerEndpoint) error {
	return errors.New("wip: wireguard not implemented")
}

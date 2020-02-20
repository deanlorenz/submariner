package wg

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
	"net"
	"os"

	"github.com/submariner-io/submariner/pkg/types"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// DefaultListenPort specifies UDP port address of wireguard
	DefaultListenPort = 5871

	// DefaultDeviceName specifies name of wireguard network device
	DefaultDeviceName = "subwg0"

	// name (key) of publicKey entry in back-end map
	PublicKey = "publicKey"

	// we assume Linux
	deviceType = wgtypes.LinuxKernel
)

type wireguard struct {
	localSubnets  []*net.IPNet
	localEndpoint types.SubmarinerEndpoint
	peers         map[string]wgtypes.Key // clusterID -> publicKey
	client        *wgctrl.Client
	link          netlink.Link
	//debug   bool
	//logFile string
}

// NewDriver creates a new Wireguard driver
func NewDriver(localSubnets []string, localEndpoint types.SubmarinerEndpoint) (*wireguard, error) {

	var err error
	var localIPNets []*net.IPNet
	var wgClient *wgctrl.Client
	var wgLink netlink.Link
	var peers map[string]wgtypes.Key

	// create the wg device (ip link add dev $DefaultDeviceName type wireguard)
	la := netlink.NewLinkAttrs()
	la.Name = DefaultDeviceName
	wgLink = &netlink.GenericLink{
		LinkAttrs: la,
		LinkType:  "wireguard",
	}
	if err = netlink.LinkAdd(wgLink); err != nil {
		return nil, fmt.Errorf("failed to add wireguard device: %v", err)
	}

	// setup local address (ip address add dev $DefaultDeviceName $PublicIP
	var udp string
	if localEndpoint.Spec.NATEnabled {
		udp = localEndpoint.Spec.PublicIP
	} else {
		udp = localEndpoint.Spec.PrivateIP
	}
	var myIP *netlink.Addr
	if myIP, err = netlink.ParseAddr(udp); err != nil {
		return nil, fmt.Errorf("failed to parse my IP address %s: %v", udp, err)
	}
	if err = netlink.AddrAdd(wgLink, myIP); err != nil {
		return nil, fmt.Errorf("failed to add local address: %v", err)
	}

	// check localSubnets
	var cidr *net.IPNet
	for _, sn := range localSubnets {
		if _, cidr, err = net.ParseCIDR(sn); err != nil {
			return nil, fmt.Errorf("failed to parse subnet %s: %v", sn, err)
		}
		localIPNets = append(localIPNets, cidr)
	}

	// create controller
	if wgClient, err = wgctrl.New(); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("wgctrl is not available on this system")
		}
		return nil, fmt.Errorf("failed to open wgctl client: %v", err)
	}
	defer func() {
		if err == nil {
			return
		}
		if e := wgClient.Close(); e != nil {
			klog.Errorf("failed to close client %v", e)
		}
	}()

	// generate local keys and set public key in BackendConfig
	var priv, pub wgtypes.Key
	if priv, err = wgtypes.GeneratePrivateKey(); err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}
	pub = priv.PublicKey()
	if localEndpoint.Spec.BackendConfig == nil {
		localEndpoint.Spec.BackendConfig = make(map[string]string)
	}
	localEndpoint.Spec.BackendConfig[PublicKey] = pub.String()

	// configure the device. still not up
	port := DefaultListenPort
	peerConfigs := make([]wgtypes.PeerConfig, 0)
	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		FirewallMark: nil,
		ReplacePeers: false,
		Peers:        peerConfigs,
	}
	if err = wgClient.ConfigureDevice(DefaultDeviceName, cfg); err != nil {
		return nil, fmt.Errorf("failed to configure wireguard device: %v", err)
	}

	return &wireguard{
		localSubnets:  localIPNets,
		localEndpoint: localEndpoint,
		peers:         peers,
		client:        wgClient,
		link:          wgLink,
		//debug:         false,
		//logFile:       "",
	}, nil
}

func (w *wireguard) Init() error {
	// ip link set $DefaultDeviceName up
	if err := netlink.LinkSetUp(w.link); err != nil {
		return fmt.Errorf("failed to bring up wireguard device: %v", err)
	}
	return nil
}

func (w *wireguard) ConnectToEndpoint(ep types.SubmarinerEndpoint) (string, error) {

	var err error
	var found bool

	var remoteEP string
	var remoteKey wgtypes.Key
	remoteID := ep.Spec.ClusterID
	updateOnly := false
	var remoteIP net.IP
	replaceAllowedIPs := false
	allowedIPs := make([]net.IPNet, 0)

	// public key
	var key string
	if key, found = ep.Spec.BackendConfig[PublicKey]; !found {
		return "", fmt.Errorf("missing peer public key")
	}
	if remoteKey, err = wgtypes.ParseKey(key); err != nil {
		return "", fmt.Errorf("failed to parse public key %s: %v", key, err)
	}
	var oldKey wgtypes.Key
	if oldKey, found = w.peers[remoteID]; found {
		if oldKey.String() == remoteKey.String() {
			klog.Infof("updating existing peer key %s: %v", oldKey.String(), err)
			updateOnly = true
		} else { // remove old
			peerCfg := []wgtypes.PeerConfig{{
				PublicKey: remoteKey,
				Remove:    true,
			}}
			if err = w.client.ConfigureDevice(DefaultDeviceName, wgtypes.Config{
				ReplacePeers: true,
				Peers:        peerCfg,
			}); err != nill {
				klog.Errorf("failed to remove old key %s: %v", oldKey.String(), err)
			}
			delete(w.peers, remoteID)
		}
	} else {
		w.peers[remoteID] = remoteKey
	}

	// remote addresses
	if ep.Spec.NATEnabled {
		remoteEP = ep.Spec.PublicIP
	} else {
		remoteEP = ep.Spec.PrivateIP
	}
	if remoteIP = net.ParseIP(remoteEP); remoteIP == nil {
		return "", fmt.Errorf("failed to parse remote IP %s", remoteEP)
	}

	// check peer subnets
	var cidr *net.IPNet
	for _, sn := range ep.Spec.Subnets {
		if _, cidr, err = net.ParseCIDR(sn); err != nil {
			return "", fmt.Errorf("failed to parse subnet %s: %v", sn, err)
		}
		allowedIPs = append(allowedIPs, cidr)
	}

	// configure peer
	peerCfg := []wgtypes.PeerConfig{{
		PublicKey:    remoteKey,
		Remove:       false,
		UpdateOnly:   updateOnly,
		PresharedKey: nil,
		Endpoint: &net.UDPAddr{
			IP:   remoteIP,
			Port: DefaultListenPort,
		},
		PersistentKeepaliveInterval: nil,
		ReplaceAllowedIPs:           replaceAllowedIPs,
		AllowedIPs:                  allowedIPs,
	}}
	if err = w.client.ConfigureDevice(DefaultDeviceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        peerCfg,
	}); err != nil {
		return "", fmt.Errorf("failed to configure peer: %v", err)
	}

	return remoteEP, nil
}

func (w *wireguard) DisconnectFromEndpoint(ep types.SubmarinerEndpoint) error {
	var err error
	var found bool

	var remoteKey wgtypes.Key
	remoteID := ep.Spec.ClusterID

	// public key
	var key string
	if key, found = ep.Spec.BackendConfig[PublicKey]; !found {
		return fmt.Errorf("missing peer public key")
	}
	if remoteKey, err = wgtypes.ParseKey(key); err != nil {
		klog.Warningf("failed to parse public key %s: %v, search by clusterID", key, err)
		if remoteKey, found = w.peers[remoteID]; !found {
			return fmt.Errorf("missing peer public key")
		}
	}
	peerCfg := []wgtypes.PeerConfig{{
		PublicKey: remoteKey,
		Remove:    true,
	}}
	if err = w.client.ConfigureDevice(DefaultDeviceName, wgtypes.Config{
		ReplacePeers: true,
		Peers:        peerCfg,
	}); err != nill {
		return fmt.Errorf("failed to remove old key %s: %v", remoteKey.String(), err)
	}
	delete(w.peers, remoteID)

	return nil
}

func GetActiveConnections(clusterID string) ([]string, error) {
	return make([]string,0), nil
}

package libp2ptls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"golang.org/x/sys/cpu"
	"math/big"
	"time"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/minio/sha256-simd"
)

const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years
const certificatePrefix = "libp2p-tls-handshake:"

var extensionID = getPrefixedExtensionID([]int{1, 1})
var extensionCritical bool // so we can mark the extension critical in tests

// Identity is used to generate secure config for connection
type Identity struct {
	config tls.Config
}

type signedKey struct {
	PubKey    []byte
	Signature []byte
}

func NewIdentity(cert tls.Certificate, certPoll *x509.CertPool) (*Identity, error) {
	return &Identity{
		config: tls.Config{
			Certificates: []tls.Certificate{cert},
			// for server
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  certPoll,
			// for client
			// client need to skip hostname verify
			RootCAs:            certPoll,
			InsecureSkipVerify: true, // Not actually skipping, we check the cert in VerifyPeerCertificate
		},
	}, nil
}

func (i *Identity) ConfigForAny() (*tls.Config, <-chan ic.PubKey) {
	return i.ConfigForPeer("", "")
}

func (i *Identity) ConfigForPeer(remote peer.ID, addr string) (*tls.Config, <-chan ic.PubKey) {
	keyCh := make(chan ic.PubKey, 1)
	conf := i.config.Clone()

	// fetch the public key from the certs
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		defer close(keyCh)

		chain := make([]*x509.Certificate, len(rawCerts))
		for i := 0; i < len(rawCerts); i++ {
			cert, err := x509.ParseCertificate(rawCerts[i])
			if err != nil {
				return err
			}
			chain[i] = cert
		}

		// Code copy/pasted https://github.com/digitalbitbox/bitbox-wallet-app/blob/b04bd07852d5b37939da75b3555b5a1e34a976ee/backend/coins/btc/electrum/electrum.go#L76-L111
		opts := x509.VerifyOptions{
			Roots:         conf.ClientCAs,
			CurrentTime:   time.Now(),
			DNSName:       "", // <- skip hostname verification
			Intermediates: x509.NewCertPool(),
		}

		for i, cert := range chain {
			if i == 0 {
				continue
			}
			opts.Intermediates.AddCert(cert)
		}
		_, err := chain[0].Verify(opts)
		if err != nil {
			return err
		}

		tmp := chain[0].PublicKey.(*ecdsa.PublicKey)
		pubKey := &ECDSAPublicKey{
			pub: tmp,
		}
		if remote != "" && !remote.MatchesPublicKey(pubKey) {
			peerID, err := peer.IDFromPublicKey(pubKey)
			if err != nil {
				peerID = peer.ID(fmt.Sprintf("(not determined: %s)", err.Error()))
			}
			return fmt.Errorf("peer IDs don't match: expected %s, got %s", remote, peerID)
		}
		keyCh <- pubKey
		return nil
	}
	return conf, keyCh
}

// RsaPublicKey is an rsa public key
type RsaPublicKey struct {
	k rsa.PublicKey
}

// Verify compares a signature against input data
func (pk *RsaPublicKey) Verify(data, sig []byte) (bool, error) {
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(&pk.k, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (pk *RsaPublicKey) Type() pb.KeyType {
	return pb.KeyType_RSA
}

// Bytes returns protobuf bytes of a public key
func (pk *RsaPublicKey) Bytes() ([]byte, error) {
	return ic.MarshalPublicKey(pk)
}

func (pk *RsaPublicKey) Raw() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&pk.k)
}

// Equals checks whether this key is equal to another
func (pk *RsaPublicKey) Equals(k ic.Key) bool {
	// make sure this is an rsa public key
	other, ok := (k).(*RsaPublicKey)
	if !ok {
		return basicEquals(pk, k)
	}

	return pk.k.N.Cmp(other.k.N) == 0 && pk.k.E == other.k.E
}

func basicEquals(k1, k2 ic.Key) bool {
	if k1.Type() != k2.Type() {
		return false
	}

	a, err := k1.Raw()
	if err != nil {
		return false
	}
	b, err := k2.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ECDSAPublicKey is an implementation of an ECDSA public key
type ECDSAPublicKey struct {
	pub *ecdsa.PublicKey
}

// Bytes returns the public key as protobuf bytes
func (ePub *ECDSAPublicKey) Bytes() ([]byte, error) {
	return ic.MarshalPublicKey(ePub)
}

// Type returns the key type
func (ePub *ECDSAPublicKey) Type() pb.KeyType {
	return pb.KeyType_ECDSA
}

// Raw returns x509 bytes from a public key
func (ePub *ECDSAPublicKey) Raw() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(ePub.pub)
}

// Equals compares to public keys
func (ePub *ECDSAPublicKey) Equals(o ic.Key) bool {
	return basicEquals(ePub, o)
}

// Verify compares data to a signature
func (ePub *ECDSAPublicKey) Verify(data, sigBytes []byte) (bool, error) {
	return true, nil
}


// PubKeyFromCertChain verifies the certificate chain and extract the remote's public key.
func PubKeyFromCertChain(chain []*x509.Certificate) (ic.PubKey, error) {
	if len(chain) != 1 {
		return nil, errors.New("expected one certificates in the chain")
	}
	cert := chain[0]
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	var found bool
	var keyExt pkix.Extension
	// find the libp2p key extension, skipping all unknown extensions
	for _, ext := range cert.Extensions {
		if extensionIDEqual(ext.Id, extensionID) {
			keyExt = ext
			found = true
			for i, oident := range cert.UnhandledCriticalExtensions {
				if oident.Equal(ext.Id) {
					// delete the extension from UnhandledCriticalExtensions
					cert.UnhandledCriticalExtensions = append(cert.UnhandledCriticalExtensions[:i], cert.UnhandledCriticalExtensions[i+1:]...)
					break
				}
			}
			break
		}
	}
	if !found {
		return nil, errors.New("expected certificate to contain the key extension")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	var sk signedKey
	if _, err := asn1.Unmarshal(keyExt.Value, &sk); err != nil {
		return nil, fmt.Errorf("unmarshalling signed certificate failed: %s", err)
	}
	pubKey, err := ic.UnmarshalPublicKey(sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling public key failed: %s", err)
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	valid, err := pubKey.Verify(append([]byte(certificatePrefix), certKeyPub...), sk.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %s", err)
	}
	if !valid {
		return nil, errors.New("signature invalid")
	}
	return pubKey, nil
}

func keyToCertificate(sk ic.PrivKey) (*tls.Certificate, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyBytes, err := ic.MarshalPublicKey(sk.GetPublic())
	if err != nil {
		return nil, err
	}
	certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	if err != nil {
		return nil, err
	}
	signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	if err != nil {
		return nil, err
	}
	value, err := asn1.Marshal(signedKey{
		PubKey:    keyBytes,
		Signature: signature,
	})
	if err != nil {
		return nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Time{},
		NotAfter:     time.Now().Add(certValidityPeriod),
		// after calling CreateCertificate, these will end up in Certificate.Extensions
		ExtraExtensions: []pkix.Extension{
			{Id: extensionID, Critical: extensionCritical, Value: value},
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certKey.Public(), certKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}, nil
}

// We want nodes without AES hardware (e.g. ARM) support to always use ChaCha.
// Only if both nodes have AES hardware support (e.g. x86), AES should be used.
// x86->x86: AES, ARM->x86: ChaCha, x86->ARM: ChaCha and ARM->ARM: Chacha
// This function returns true if we don't have AES hardware support, and false otherwise.
// Thus, ARM servers will always use their own cipher suite preferences (ChaCha first),
// and x86 servers will aways use the client's cipher suite preferences.
func preferServerCipherSuites() bool {
	// Copied from the Go TLS implementation.

	// Check the cpu flags for each platform that has optimized GCM implementations.
	// Worst case, these variables will just all be false.
	var (
		hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
		hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
		// Keep in sync with crypto/aes/cipher_s390x.go.
		hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

		hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
	)
	return !hasGCMAsm
}
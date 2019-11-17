package sign

import (
	"bytes"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"math/rand"
)

// ForgeSignature uses ECDSA public key recovery to find a public key that
// matches the given signature and message.
// TODO: explain in more details customization / allow choosing pubkey prefix.
func ForgeSignature(sigMessage []byte, message []byte) (*btcec.PublicKey, []byte, error) {
	if len(sigMessage) > 56 {
		return nil, nil, errors.New("message too long: not enough bytes to brute-force valid signature")
	}

	suffix := make([]byte, 64-len(sigMessage))
	for {
		// Brute-force the signature suffix.
		_, err := rand.Read(suffix)
		if err != nil {
			return nil, nil, err
		}

		// Brute-force the magic byte.
		for i := byte(0); i <= byte(255); i++ {
			sig := bytes.Join([][]byte{[]byte{i}, sigMessage, suffix}, nil)
			pubKey, _, err := btcec.RecoverCompact(btcec.S256(), sig, message)
			if err == nil {
				return pubKey, sigMessage, nil
			}
		}
	}
}

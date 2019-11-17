package sign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"math/big"
	"testing"
)

func TestPubKeyRecovery(t *testing.T) {
	message, err := hex.DecodeString("4242424242424242424242424242424242424242424242424242424242424242")
	if err != nil {
		t.Fatal(err)
	}

	sk, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}

	compactSig, err := btcec.SignCompact(btcec.S256(), sk, message, true)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Compact signature: %x", compactSig)

	r := big.NewInt(0).SetBytes(compactSig[1:33])
	s := big.NewInt(0).SetBytes(compactSig[33:])
	if !ecdsa.Verify(sk.PubKey().ToECDSA(), message, r, s) {
		t.Fatal("invalid signature")
	}

	pubKey, _, err := btcec.RecoverCompact(btcec.S256(), compactSig, message)
	if err != nil {
		t.Fatal(err)
	}

	if !pubKey.IsEqual(sk.PubKey()) {
		t.Fatalf("invalid public key recovered: expected %x, got %x", sk.PubKey().SerializeCompressed(), pubKey.SerializeCompressed())
	}
}

func TestForgeSignature(t *testing.T) {
	// TODO: use real vanity messages (in Base58 with Bitcoin encoding stuff).
	vanity, err := hex.DecodeString("424242424242424242424242424242424242424242424242424242424242424242424242424242424242")
	if err != nil {
		t.Fatal(err)
	}

	message, err := hex.DecodeString("4242424242424242424242424242424242424242424242424242424242424242")
	if err != nil {
		t.Fatal(err)
	}

	pubKey, sig, err := ForgeSignature(vanity, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("invalid signature length: %x", sig)
	}

	r := big.NewInt(0).SetBytes(sig[1:33])
	s := big.NewInt(0).SetBytes(sig[33:])
	if !ecdsa.Verify(pubKey.ToECDSA(), message, r, s) {
		t.Fatalf("invalid signature generated: %x", sig)
	}

	t.Logf("Valid signature found: (%x, %x)", pubKey.SerializeCompressed(), sig)
}

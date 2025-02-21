package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	gotpm2 "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/snapcore/secboot/tpm2"
)

func hashCounter(name []byte) []byte {
	h := sha256.New()
	h.Write([]byte("AUTH-PCR-POLICY"))
	h.Write(name)
	return h.Sum(nil)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "error: expected 2 arguments!")
		os.Exit(1)
	}
	keyFile := os.Args[1]
	namehex := os.Args[2]

	data, err := tpm2.ReadSealedKeyObjectFromFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	d := data.GetData()
	sp := d.StaticPolicy()
	pk := sp.GetPublicKey()
	dp := d.DynamicPolicy()
	sig := dp.GetSig()

	counter := d.PcrPolicyCounterHandle()
	fmt.Printf("Key uses nv index 0x%08x\n", counter)
	name := make([]byte, hex.DecodedLen(len(namehex)))
	_, err = hex.Decode(name, []byte(namehex))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}

	pcrpolicyhash := hashCounter(name)

	authorizedPolicy := dp.GetPolicyDigest()

	h2 := pk.NameAlg.NewHash()
	h2.Write(authorizedPolicy)
	h2.Write(pcrpolicyhash)
	hash := h2.Sum(nil)

	var r big.Int
	var s big.Int
	r.SetBytes(sig.Signature.ECDSA.SignatureR)
	s.SetBytes(sig.Signature.ECDSA.SignatureS)
	pub, ok := pk.Public().(*ecdsa.PublicKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	match := ecdsa.Verify(pub, hash, &r, &s)
	if !match {
		fmt.Fprintf(os.Stderr, "signature does not match\n")
		os.Exit(1)
	}

	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	tpm := gotpm2.NewTPMContext(tcti)
	defer tpm.Close()

	authorizeKey, err := tpm.LoadExternal(nil, pk, gotpm2.HandleOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	defer tpm.FlushContext(authorizeKey)

	_, err = tpm.VerifySignature(authorizeKey, hash, sig)
	if err == nil {
		fmt.Fprintf(os.Stderr, "The TPM validated the signature correctly.\n")
		os.Exit(0)
	} else {
		fmt.Fprintf(os.Stderr, "The TPM did not validate the signature: %v\n", err)
		os.Exit(1)
	}
}

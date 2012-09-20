package tack

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
	"tackgo/tack/util"
)

const TACK_LENGTH = 166
const PUBKEY_LENGTH = 64
const HASH_LENGTH = 32
const SIG_LENGTH = 64

type Tack struct {
	PublicKey     []byte // PUBKEY_LENGTH
	MinGeneration uint8
	Generation    uint8
	Expiration    uint32
	TargetHash    []byte // HASH_LENGTH
	Signature     []byte // SIG_LENGTH
}

func NewTack(publicKey []byte, minGeneration uint8, generation uint8,
	expiration uint32, targetHash []byte, signature []byte) (*Tack, error) {
	if minGeneration > generation {
		return nil, errors.New("minGeneration > generation")
	}
	if len(publicKey) != PUBKEY_LENGTH {
		return nil, fmt.Errorf("publicKey is the wrong size: %d", len(publicKey))
	}
	if len(targetHash) != HASH_LENGTH {
		return nil, fmt.Errorf("targetHash is the wrong size: %d", len(targetHash))
	}
	if len(signature) != SIG_LENGTH {
		return nil, fmt.Errorf("signature is the wrong size: %d", len(signature))
	}
	return &Tack{publicKey, minGeneration, generation, expiration, targetHash, 
		signature}, nil
}

func NewTackFromBytes(b []byte) (*Tack, error) {
	if len(b) != TACK_LENGTH {
		return nil, fmt.Errorf("Tack is the wrong size: %d", len(b))
	}
	t, i := Tack{}, 0
	t.PublicKey = b[:PUBKEY_LENGTH]
	i += PUBKEY_LENGTH
	t.MinGeneration = b[i]
	t.Generation = b[i+1]
	t.Expiration = uint32(b[i+2])<<24 | uint32(b[i+3])<<16 | uint32(b[i+4])<<8 | 
		uint32(b[i+5])
	t.TargetHash = b[i+6 : i+6+HASH_LENGTH]
	i += 6 + HASH_LENGTH
	t.Signature = b[i : i+SIG_LENGTH]
	if t.MinGeneration > t.Generation {
		return nil, errors.New("MinGeneration > Generation")
	}
	return &t, nil
}

func NewTackFromPem(s string) (*Tack, error) {
	b, err := util.Depem(s, "TACK")
	if err != nil {
		return nil, err
	}
	return NewTackFromBytes(b)
}

func (t *Tack) serializePreSig() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, TACK_LENGTH))
	buf.Write(t.PublicKey)
	buf.WriteByte(t.MinGeneration)
	buf.WriteByte(t.Generation)
	binary.Write(buf, binary.BigEndian, t.Expiration)
	buf.Write(t.TargetHash)
	return buf.Bytes()
}

func (t *Tack) Serialize() []byte {
	b := t.serializePreSig()
	return append(b, t.Signature...)
}

func (t *Tack) SerializeAsPem() string {
	b := t.Serialize()
	return util.Pem(b, "TACK")
}

func (t *Tack) GetKeyFingerprint() KeyFingerprint {
	return NewKeyFingerprintFromBytes(t.PublicKey)
}

func (t *Tack) String() string {
	s := fmt.Sprintf(
		`key fingerprint = %s
min_generation  = %d
generation      = %d
expiration      = %s
target_hash     = %s
`, t.GetKeyFingerprint(), t.MinGeneration, t.Generation,
		util.MinutesToString(t.Expiration), util.BytesToHexString(t.TargetHash))
	return s
}

func (t *Tack) hashForSig() []byte {
	b := t.serializePreSig()
	hash := sha256.New()
	hash.Write([]byte("tack_sig"))
	hash.Write(b)
	return hash.Sum(nil)
}

func (t *Tack) Sign(privKey *ecdsa.PrivateKey) error {
	x, y := privKey.X, privKey.Y
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	xPad := PUBKEY_LENGTH/2 - len(xBytes)
	yPad := PUBKEY_LENGTH/2 - len(yBytes)
	copy(t.PublicKey[xPad:PUBKEY_LENGTH/2], xBytes)
	copy(t.PublicKey[PUBKEY_LENGTH/2+yPad:], yBytes)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, t.hashForSig())
	if err != nil {
		return err
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPad := SIG_LENGTH/2 - len(rBytes)
	sPad := SIG_LENGTH/2 - len(sBytes)
	copy(t.Signature[rPad:SIG_LENGTH/2], rBytes)
	copy(t.Signature[SIG_LENGTH/2+sPad:], sBytes)
	return nil
}

func (t *Tack) Verify() bool {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, append([]byte{4}, t.PublicKey...))
	pubKey := ecdsa.PublicKey{curve, x, y}

	var r, s big.Int
	r.SetBytes(t.Signature[:SIG_LENGTH/2])
	s.SetBytes(t.Signature[SIG_LENGTH/2:])
	return ecdsa.Verify(&pubKey, t.hashForSig(), &r, &s)
}

func (t *Tack) WellFormed(currentTime time.Time, spkiHash []byte) error {
	if t.MinGeneration > t.Generation {
		return errors.New("MinGeneration > Generation")
	}
	if currentTime.Unix() > int64(t.Expiration)*60 {
		return ExpirationError{}
	}
	if !bytes.Equal(t.TargetHash, spkiHash) {
		return fmt.Errorf("TargetHash not correct: target_hash=%v, spki hash=%v", 
			t.TargetHash, spkiHash)
	}
	if !t.Verify() {
		return errors.New("Signature not correct")
	}
	return nil
}

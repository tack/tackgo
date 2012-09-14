package structures

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"crypto/elliptic"
	"crypto/ecdsa"
	"crypto/sha256"
	"tackgo/util"	
)

const TACK_LENGTH = 166
const PUBKEY_LENGTH = 64
const HASH_LENGTH = 32
const SIG_LENGTH = 64

type Tack struct {
	PublicKey     []byte  // PUBKEY_LENGTH
	MinGeneration uint8
	Generation    uint8
	Expiration    uint32
	TargetHash    []byte  // HASH_LENGTH
	Signature     []byte  // SIG_LENGTH
}

func NewTack(publicKey []byte, minGeneration uint8, generation uint8,
	 		expiration uint32, targetHash []byte, signature []byte) (*Tack, error) {
	t := Tack{}
	t.PublicKey = append(t.PublicKey, publicKey[ : PUBKEY_LENGTH]...)
	t.MinGeneration = minGeneration
	t.Generation = generation
	t.Expiration = expiration
	t.TargetHash = append(t.TargetHash, targetHash[ : HASH_LENGTH]...)
	t.Signature = append(t.Signature, signature[ : SIG_LENGTH]...)
	return &t, nil
}

func NewTackFromBytes(b []byte) (*Tack, error) {
	if len(b) != TACK_LENGTH {
		return nil, fmt.Errorf("Tack is the wrong size: %d", len(b))
	}
	buf := bytes.NewBuffer(b)
	t := Tack{}
	t.PublicKey = append(t.PublicKey, buf.Next(PUBKEY_LENGTH)...)
	t.MinGeneration, _ = buf.ReadByte()
	t.Generation, _ = buf.ReadByte()
	binary.Read(buf, binary.BigEndian, &t.Expiration)
	t.TargetHash = append(t.TargetHash, buf.Next(HASH_LENGTH)...)
	t.Signature = append(t.Signature, buf.Next(SIG_LENGTH)...)
	return &t, nil
}

func NewTackFromPem(s string) (*Tack, error) {
	b, err := util.Depem(s, "TACK")
	if err != nil {return nil, err}
	return NewTackFromBytes(b)
}

func (t *Tack) Serialize() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, TACK_LENGTH))
	buf.Write(t.PublicKey)
	buf.WriteByte(t.MinGeneration)
	buf.WriteByte(t.Generation)
	binary.Write(buf, binary.BigEndian, t.Expiration)
	buf.Write(t.TargetHash)
	buf.Write(t.Signature)
	return buf.Bytes()
}

func (t *Tack) SerializeAsPem() string {
	b := t.Serialize()
	return util.Pem(b, "TACK")
}

func (t *Tack) KeyFingerprint() string {
	return util.KeyFingerprint(t.PublicKey)
}

func (t *Tack) String() string {
	s := fmt.Sprintf(
`key fingerprint = %s
min_generation  = %d
generation      = %d
expiration      = %s
target_hash     = %s
`,
	t.KeyFingerprint(),
    t.MinGeneration,
    t.Generation,
    util.MinutesToString(t.Expiration),
    util.BytesToHexString(t.TargetHash))
	return s
}

func (t *Tack) Verify() bool {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, append([]byte{4}, t.PublicKey...)) 
	pubKey := ecdsa.PublicKey{curve, x, y}
	
	var r, s big.Int
	r.SetBytes(t.Signature[ : SIG_LENGTH/2])
	s.SetBytes(t.Signature[SIG_LENGTH/2 : ])
	
	b := t.Serialize()
	hash := sha256.New()
	hash.Write([]byte("tack_sig"))
	hash.Write(b[ : len(b) - SIG_LENGTH])
	hresult := hash.Sum(nil)
	
	return ecdsa.Verify(&pubKey, hresult, &r, &s) 
}

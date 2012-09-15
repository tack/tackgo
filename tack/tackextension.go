package tack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"tackgo/tack/util"
)

type TackExtension struct {
	Tacks           []*Tack
	ActivationFlags uint8
}

func NewTackExtension(tacks []*Tack, activationFlags uint8) (*TackExtension, error) {
	te:= TackExtension{}
	copy(te.Tacks[:], tacks)
	te.ActivationFlags = activationFlags
	return &te, nil
}

func NewTackExtensionFromBytes(b []byte) (*TackExtension, error) {
	if (len(b) != 3+TACK_LENGTH) && (len(b) != 3+2*TACK_LENGTH) {
		return nil, fmt.Errorf("TackExtension is the wrong size: %d", len(b))
	}

	buf := bytes.NewBuffer(b)
	var lenTacks uint16
	binary.Read(buf, binary.BigEndian, &lenTacks)
	if int(lenTacks)+3 != len(b) {
		return nil, fmt.Errorf("Tacks field is the wrong size: %d", lenTacks)
	}

	te := TackExtension{}
	for {
		tack, err := NewTackFromBytes(buf.Next(TACK_LENGTH))
		if err != nil {return nil, err}

		te.Tacks = append(te.Tacks, tack)
		if buf.Len() == 1 {
			break
		}
	}
	te.ActivationFlags = b[0]
	return &te, nil
}

func NewTackExtensionFromPem(s string) (*TackExtension, error) {
	b, err := util.Depem(s, "TACK EXTENSION")
	if err != nil {return nil, err}
	return NewTackExtensionFromBytes(b)
}

func (te *TackExtension) Serialize() []byte {
	lenTacks := len(te.Tacks) * TACK_LENGTH
	b := make([]byte, 0, lenTacks+3)
	b = append(b, uint8(lenTacks>>8), uint8(lenTacks))
	for _, tack := range te.Tacks {
		b = append(b, tack.Serialize()...)
	}
	b = append(b, te.ActivationFlags)
	return b
}

func (te *TackExtension) SerializeAsPem() string {
	b := te.Serialize()
	return util.Pem(b, "TACK EXTENSION")
}

func (te *TackExtension) String() string {
	s := ""
	for _, t := range te.Tacks {
		s = s + t.String() 
	}
	s = s + fmt.Sprintf("activation_flags = %d\n", te.ActivationFlags)
	return s
}

func (te *TackExtension) Len() int {
	return 3 + len(te.Tacks)*TACK_LENGTH
}

package tack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

type TackExtension struct {
	Tacks           []*Tack
	ActivationFlags uint8
}

func NewTackExtension(tacks []*Tack, activationFlags uint8) (*TackExtension, error) {
	if len(tacks) == 0 {
		return nil, errors.New("No tacks for TackExtension")
	}
	if len(tacks) > 2 {
		return nil, fmt.Errorf("Too many tacks for TackExtension: %d", len(tacks))
	}
	if activationFlags > 3 {
		return nil, fmt.Errorf("Bad activationFlags: %d", activationFlags)
	}
	return &TackExtension{tacks, activationFlags}, nil
}

func NewTackExtensionFromBytes(b []byte) (*TackExtension, error) {
	if (len(b) != 3+TACK_LENGTH) && (len(b) != 3+2*TACK_LENGTH) {
		return nil, fmt.Errorf("TackExtension is the wrong size: %d", len(b))
	}

	buf := bytes.NewBuffer(b)
	var lenTacks uint16
	binary.Read(buf, binary.BigEndian, &lenTacks)
	if int(lenTacks)+3 != len(b) {
		return nil, TacksLengthError{}
	}

	te := TackExtension{}
	for {
		tack, err := NewTackFromBytes(buf.Next(TACK_LENGTH))
		if err != nil {
			return nil, err
		}

		te.Tacks = append(te.Tacks, tack)
		if buf.Len() == 1 {
			break
		}
	}
	te.ActivationFlags, _ = buf.ReadByte()
	if te.ActivationFlags > 3 {
		return nil, ActivationFlagsError{}
	}

	return &te, nil
}

func NewTackExtensionFromPem(s string) (*TackExtension, error) {
	b, err := depem(s, "TACK EXTENSION")
	if err != nil {
		return nil, err
	}
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
	return pem(b, "TACK EXTENSION")
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

func (te *TackExtension) IsActive(tackIndex int) bool {
	return ((te.ActivationFlags & (1 << uint8(tackIndex))) != 0)
}

func (te *TackExtension) GetKeyFingerprints() []KeyFingerprint {
	fingerprints := make([]KeyFingerprint, 0, 2)
	for _, tack := range te.Tacks {
		fingerprints = append(fingerprints, tack.GetKeyFingerprint())
	}
	return fingerprints
}

func (te *TackExtension) WellFormed(currentTime time.Time, spkiHash []byte) error {
	if len(te.Tacks) < 1 || len(te.Tacks) > 2 {
		return errors.New("Wrong number of tacks")
	}

	for _, t := range te.Tacks {
		if err := t.WellFormed(currentTime, spkiHash); err != nil {
			return err
		}
	}
	if len(te.Tacks) == 2 {
		if bytes.Equal(te.Tacks[0].PublicKey, te.Tacks[1].PublicKey) {
			return DuplicateTackKeysError{}
		}
	}
	if te.ActivationFlags < 0 || te.ActivationFlags > 3 {
		return ActivationFlagsError{}
	}
	return nil
}

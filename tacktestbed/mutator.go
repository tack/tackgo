package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"math/rand"
	"tack"
)

type PinState struct {
	initialTime uint32
	endTime uint32
	minGeneration uint8
	publicKey []byte
	privKey *ecdsa.PrivateKey
}

type HostState struct {
	name string
	pinStates []PinState
}

func randRange(min int, max int) int {
	return min + rand.Intn(max + 1 - min)
}

func NewPinState() *PinState{
	state := PinState{}
	var err error
	state.privKey, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if (err != nil) { panic(err.Error())}
	state.publicKey = make([]byte, 64)
	x, y := state.privKey.X, state.privKey.Y
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	xPad := tack.PUBKEY_LENGTH/2 - len(xBytes)
	yPad := tack.PUBKEY_LENGTH/2 - len(yBytes)
	copy(state.publicKey[xPad : tack.PUBKEY_LENGTH/2], xBytes)
	copy(state.publicKey[tack.PUBKEY_LENGTH/2+yPad : ], yBytes)
	return &state
}

func (state* PinState) new(targetHash []byte) *tack.Tack {

	tack, err := tack.NewTack(state.publicKey, state.minGeneration, state.minGeneration, 0xFFFFFFFF, 
		targetHash, make([]byte, 64)) 
	if (err!=nil) { panic(err.Error())}
	tack.Sign(state.privKey)		
	return tack
}

func (state* PinState) next(targetHash []byte) *tack.Tack {
	diceToss := randRange(1,3)
	switch (diceToss) {
	case 1: break
	case 2:
		if state.minGeneration < 255 {
			state.minGeneration = state.minGeneration + 1
		}
	case 3: state.minGeneration = uint8(randRange(int(state.minGeneration), 255))
	}

	diceToss = randRange(1,3)
	var generation uint8
	switch (diceToss) {
	case 1: generation = state.minGeneration
	case 2: 
		if state.minGeneration < 255 {
			generation = state.minGeneration + 1
		} else {
			generation = state.minGeneration
		}
	case 3: generation = uint8(randRange(int(state.minGeneration), 255))
	}
	
	tack, err := tack.NewTack(state.publicKey, state.minGeneration, generation, 0xFFFFFFFF, 
		targetHash, make([]byte, 64)) 
	if (err!=nil) { panic("")}
	tack.Sign(state.privKey)		
	return tack
}

/*
- randomize generation within (minGen, 255)
- randomly add to minGen
- corrupt public key or signature
- expired tack
- activation flag on or off

- minGen
- gen
- corrupt publicKey or signature
- corrupt length field
- corrupt activation_flags
- corrupt target_hash
- expired tack
- accepted / rejected / unpinned
*/
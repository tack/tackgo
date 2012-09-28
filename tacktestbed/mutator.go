package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"math/rand"
	"tack"
)

func randRange(min int, max int) int {
	return min + rand.Intn(max + 1 - min)
}

type PinState struct {
	//initialTime uint32
	//endTime uint32

	privKey *ecdsa.PrivateKey
	publicKey []byte

	minGeneration uint8	
	generation uint8
	expirationTime uint32
	targetHash []byte

	currentTime uint32

	tack *tack.Tack
}

func NewPinState(targetHash []byte) *PinState{
	state := PinState{}
	var err error

	// Generate private key
	state.privKey, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if (err != nil) { panic(err.Error())}

	// Populate public key
	state.publicKey = make([]byte, 64)
	x, y := state.privKey.X, state.privKey.Y
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	xPad := tack.PUBKEY_LENGTH/2 - len(xBytes)
	yPad := tack.PUBKEY_LENGTH/2 - len(yBytes)
	copy(state.publicKey[xPad : tack.PUBKEY_LENGTH/2], xBytes)
	copy(state.publicKey[tack.PUBKEY_LENGTH/2+yPad : ], yBytes)

	// Initialize other vars
	state.minGeneration = 0
	state.generation = 0
	state.currentTime = 123
	state.expirationTime = 30000000
	state.targetHash = targetHash
	state.createTack()

	return &state
}

func (state* PinState) createTack() {
	tack, err := tack.NewTack(state.publicKey, state.minGeneration, state.generation, 
		state.expirationTime, state.targetHash, make([]byte, 64)) 
	if (err!=nil) { panic(err.Error())}
	tack.Sign(state.privKey)
	state.tack = tack
}

func (state* PinState) next() {
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
	switch (diceToss) {
	case 1: state.generation = state.minGeneration
	case 2: 
		if state.minGeneration < 255 {
			state.generation = state.minGeneration + 1
		} else {
			state.generation = state.minGeneration
		}
	case 3: state.generation = uint8(randRange(int(state.minGeneration), 255))
	}
	
	state.createTack()
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
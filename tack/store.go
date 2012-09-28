package tack

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

type Pin struct {
	initialTime uint32
	endTime     uint32
	fingerprint KeyFingerprint
}

type PinStore interface {
	GetPinActivation() bool // Should pin activation be performed

	GetMinGeneration(fingerprint KeyFingerprint) (minGeneration uint8, ok bool)
	SetMinGeneration(fingerprint KeyFingerprint, minGeneration uint8)

	GetPinPair(name string) []*Pin
	SetPinPair(name string, pair []*Pin)
}

type DefaultStore struct {
	PinActivation bool
	keys          map[KeyFingerprint]uint8 // fingerprints -> minGenerations
	pins          map[string][]*Pin        // names -> Pins
}

func NewDefaultStore(pinActivation bool) *DefaultStore {
	store := &DefaultStore{}
	store.PinActivation = pinActivation
	store.keys = make(map[KeyFingerprint]uint8)
	store.pins = make(map[string][]*Pin)
	return store
}

func (store *DefaultStore) GetPinActivation() bool {
	return store.PinActivation
}

func (store *DefaultStore) GetMinGeneration(fingerprint KeyFingerprint) (uint8, bool) {
	minGeneration, ok := store.keys[fingerprint]
	return minGeneration, ok
}

func (store *DefaultStore) SetMinGeneration(fingerprint KeyFingerprint, minGen uint8) {
	store.keys[fingerprint] = minGen
}

func (store *DefaultStore) GetPinPair(name string) (pins []*Pin) {
	return store.pins[name]
}

func (store *DefaultStore) SetPinPair(name string, pins []*Pin) {
	store.pins[name] = pins
}

func (store *DefaultStore) AddPin(name string, pin *Pin) error {
	pair := store.GetPinPair(name)
	if len(pair) == 2 {
		return errors.New("Adding too many pins to pair")
	}
	pair = append(pair, pin)
	store.SetPinPair(name, pair)
	return nil
}

func (store *DefaultStore) String() string {
	entries := make([]string, 0, len(store.pins))
	for name, pinPair := range store.pins {
		for _, pin := range pinPair {
			minGeneration := store.keys[pin.fingerprint]
			entry := fmt.Sprintf("[\"%v\", \"%v\", %v, %v, %v]",
				name, pin.fingerprint, minGeneration, pin.initialTime, pin.endTime)
			entries = append(entries, entry)
		}
	}
	sort.Strings(entries)
	return "[\n" + strings.Join(entries, ",\n") + "\n]"
}

func NewDefaultStoreFromJSON(s string) (store *DefaultStore, err error) {

	store = &DefaultStore{}
	store.pins = make(map[string][]*Pin)
	store.keys = make(map[KeyFingerprint]uint8)

	var stuff interface{}

	// Handle any panics from unchecked type assertions
	defer func() {
		if r := recover(); r != nil {
			err = PinListError{}
		}
	}()

	err = json.Unmarshal([]byte(s), &stuff)
	if err != nil {
		return nil, PinListError{}
	}

	topArray := stuff.([]interface{})
	for _, entry := range topArray {
		fieldArray := entry.([]interface{})
		name := fieldArray[0].(string)
		fingerprintStr := fieldArray[1].(string)
		minGeneration := fieldArray[2].(float64)
		initialTime := fieldArray[3].(float64)
		endTime := fieldArray[4].(float64)

		fingerprint, err := NewKeyFingerprintFromString(fingerprintStr)
		if err != nil {
			return nil, PinListError{}
		}
		if initialTime < 0 || initialTime > math.MaxUint32 {
			return nil, PinListError{}
		}
		if endTime < 0 || endTime > math.MaxUint32 {
			return nil, PinListError{}
		}

		store.SetMinGeneration(fingerprint, uint8(minGeneration))
		err = store.AddPin(name, &Pin{uint32(initialTime), uint32(endTime), fingerprint})
		if err != nil {
			return nil, PinListError{}
		}
	}

	return store, err
}

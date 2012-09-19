package tack

type Pin struct {
	initialTime uint32
	endTime     uint32
	fingerprint string
}

type PinStore interface {
	GetPinActivation() bool // Should pin activation be performed

	GetMinGeneration(fingerprint string) (minGeneration uint8, ok bool)
	SetMinGeneration(fingerprint string, minGeneration uint8)

	GetPinPair(name string) (pin []*Pin)
	SetPinPair(name string, pin []*Pin)
}

type DefaultStore struct {
	PinActivation bool
	keys map[string] uint8  // fingerprints -> minGenerations
	pins map[string] []*Pin // names -> Pins
}

func (store *DefaultStore) GetPinActivation() bool {
	return store.PinActivation
}

func (store *DefaultStore) GetMinGeneration(fingerprint string) (uint8, bool) {
	minGeneration, ok := store.keys[fingerprint]
	return minGeneration, ok
}

func (store *DefaultStore) SetMinGeneration(fingerprint string, minGeneration uint8) {
	store.keys[fingerprint] = minGeneration
}

func (store *DefaultStore) GetPinPair(name string) (pins []*Pin) {
	return store.pins[name]
}

func (store *DefaultStore) SetPinPair(name string, pins []*Pin) {
	store.pins[name] = pins
}

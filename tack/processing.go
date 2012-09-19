package tack

type Status int
const (
	UNPINNED Status = iota
	ACCEPTED
	REJECTED
)

func ProcessStore(tackExt *TackExtension, store PinStore, name string, 
	currentTime uint32) (status Status, err error) {

	tackMatchesPin := []bool{false, false}
	newPins := []*Pin{}   // Used for pin activation
	madeChanges := false  // Used for pin activation

	// Check tack generations and update min_generations
	tackFingerprints := tackExt.GetKeyFingerprints()
	for t, tack := range tackExt.Tacks {
		minGeneration, ok := store.GetMinGeneration(tackFingerprints[t])
		if ok {
			if tack.Generation < minGeneration {
				return status, RevokedError{}
			} else if tack.MinGeneration > minGeneration {
				store.SetMinGeneration(tackFingerprints[t], tack.MinGeneration)
			}
		}
	}

    /* Iterate over pins and tacks, calculating the return status
       and handling the first step of pin activation (delete and activate) */
	for _, pin := range store.GetPinPair(name)  {		
		pinIsActive, pinMatchesTack, pinMatchesActiveTack := false, false, false

		// Fill in variables indicating pin/tack matches
		if pin.endTime > currentTime {
			pinIsActive = true
		}
		for t, _ := range tackExt.Tacks {
			if pin.fingerprint == tackFingerprints[t] {
				pinMatchesTack = true
				pinMatchesActiveTack = tackExt.IsActive(t)
				tackMatchesPin[t] = true
			}
		}

		// Determine the store's status
		if pinIsActive {
			if !pinMatchesTack {
				return REJECTED, nil // return immediately
			}
			status = ACCEPTED
		} 

        // Pin activation (first step: consider each pin for deletion / activation)
		if store.GetPinActivation() {
			if !pinMatchesActiveTack {
				madeChanges = true  // Delete pin (by not appending to newPair)
			} else {
				endTime := pin.endTime
				if pinMatchesActiveTack && currentTime > pin.initialTime {
					endTime = currentTime + (currentTime - pin.initialTime) - 1
					if endTime > currentTime + (30*24*60) {
						endTime = currentTime + (30*24*60)
					}
					if endTime != pin.endTime {
						madeChanges = true  // Activate pin
					}
				}
                // Append old pin to newPair, possibly extending endTime
				if len(newPins) > 1 {panic("ASSERT: only 2 pins allowed in pair");}
				newPins = append(newPins, &Pin{pin.initialTime, endTime, pin.fingerprint})
			}
		}
	}

	// Pin activation (second step: add new pins)
	if store.GetPinActivation() {
		for t, tack := range tackExt.Tacks {
			if tackExt.IsActive(t) && !tackMatchesPin[t] {
				if len(newPins) > 1 {panic("ASSERT: only 2 pins allowed in pair");}
				newPins = append(newPins, &Pin{currentTime, 0, tackFingerprints[t]})
				madeChanges = true  // Add pin
				store.SetMinGeneration(tackFingerprints[t], tack.MinGeneration)
			}
		}
		// Commit pin changes
		if madeChanges {
			store.SetPinPair(name, newPins)
		}
	}

	return status, err
}

package tack

// Returned by Tack/TackExtension.WellFormed
type ExpirationError struct {}
func (err ExpirationError) Error() string {return "Tack is expired"}

// Returned by ProcessStore
type RevokedError struct {}
func (err RevokedError) Error() string {return "Tack is revoked"}

// Returned by NewDefaultStoreFromJSON
type PinListError struct {}
func (err PinListError) Error() string {return "Pin list is invalid"}

// Returned by NewKeyFingerprintFromString
type FingerprintError struct {}
func (err FingerprintError) Error() string {return "Fingerprint is invalid"}

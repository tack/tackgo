package tack

// Returned by Tack/TackExtension.WellFormed
type ExpirationError struct {}
func (err ExpirationError) Error() string {return "Tack is expired"}

// Returned by ProcessStore
type RevokedError struct {}
func (err RevokedError) Error() string {return "Tack is revoked"}

package tack

// Tack-related
type ExpirationError struct {}
func (err ExpirationError) Error() string {return "Tack is expired"}

type RevokedError struct {}
func (err RevokedError) Error() string {return "Tack is revoked"}

type GenerationError struct {}
func (err GenerationError) Error() string {return "Tack generation is invalid"}

type TargetHashError struct {}
func (err TargetHashError) Error() string {return "Tack target_hash is incorrect"}

type SignatureError struct {}
func (err SignatureError) Error() string {return "Tack signature is incorrect"}

// TackExtension-related
type ActivationFlagsError struct {}
func (err ActivationFlagsError) Error() string {return "Activation_flags is invalid"}

type TacksLengthError struct {}
func (err TacksLengthError) Error() string {return "Tacks length field is invalid"}

type DuplicateTackKeysError struct {}
func (err DuplicateTackKeysError) Error() string {return "Two tacks with same key"}

// Text processing
type FingerprintError struct {}
func (err FingerprintError) Error() string {return "Fingerprint is invalid"}

type PinListError struct {}
func (err PinListError) Error() string {return "Pin list is invalid"}

type PemError struct {s string}
func (err PemError) Error() string {return err.s}



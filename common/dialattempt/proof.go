// Package dialattempt carries adapter-owned evidence about failed connection
// establishment. Error text or a generic DialContext failure is not evidence.
package dialattempt

import "errors"

type beforeApplicationData struct{ cause error }

func (e *beforeApplicationData) Error() string { return e.cause.Error() }
func (e *beforeApplicationData) Unwrap() error { return e.cause }

// BeforeApplicationData may be called only where the adapter proves that no
// application payload was submitted and its failed attempt owns no connection.
func BeforeApplicationData(err error) error {
	if err == nil {
		return nil
	}
	return &beforeApplicationData{cause: err}
}
func ProvenBeforeApplicationData(err error) bool {
	var proof *beforeApplicationData
	return errors.As(err, &proof)
}

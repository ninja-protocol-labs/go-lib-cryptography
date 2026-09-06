package encoding

// decodeInto is the shared implementation of every codec's DecodeInto: run
// the codec's own Decode, then hold it to the destination's length.
func decodeInto(dst []byte, decoded []byte, err error) error {
	if err != nil {
		return err
	}
	if len(decoded) != len(dst) {
		return ErrInvalidLength
	}
	copy(dst, decoded)
	return nil
}

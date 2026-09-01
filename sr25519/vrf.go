package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
)

// VRF (Verifiable Random Function) sign and verify.
//
// How the (context, message) pair is turned into the transcript the VRF
// actually operates on is this package's own choice, not a wire format
// mandated by schnorrkel or any spec: schnorrkel's VRF takes an arbitrary
// Merlin transcript and leaves its construction to the caller. Real
// chains that use this VRF (Polkadot/Substrate) build that transcript out
// of protocol-specific material (block number, epoch randomness, ...),
// which is exactly the kind of protocol logic this library stays out of
// — so cross-verifying a VRF output produced by this package against a
// chain's own VRF usage isn't meaningful, only against another call to
// this same package's SignVRF/VerifyVRF. SignVRF and VerifyVRF each build
// this transcript themselves (merlin.NewTranscript(string(context)),
// appending message under the label "message") rather than sharing a
// helper, the same reasoning as sign.go's Sign/Verify.

// VRFOutput is a 32-byte VRF output.
type VRFOutput struct {
	out [VRFOutputLen]byte
}

// VRFOutputFromBytes parses a 32-byte VRF output, verifying it decodes to
// a canonically-encoded Ristretto point.
func VRFOutputFromBytes(b []byte) (*VRFOutput, error) {
	if len(b) != VRFOutputLen {
		return nil, ErrInvalidVRFOutput
	}
	var enc [VRFOutputLen]byte
	copy(enc[:], b)
	if _, err := schnorrkel.NewOutput(enc); err != nil {
		return nil, ErrInvalidVRFOutput
	}
	return &VRFOutput{
		out: enc,
	}, nil
}

// Bytes returns the 32-byte encoding of the VRF output.
func (o *VRFOutput) Bytes() [VRFOutputLen]byte {
	return o.out
}

// VRFProof is a 64-byte VRF proof.
type VRFProof struct {
	proof [VRFProofLen]byte
}

// VRFProofFromBytes parses a 64-byte VRF proof.
func VRFProofFromBytes(b []byte) (*VRFProof, error) {
	if len(b) != VRFProofLen {
		return nil, ErrInvalidVRFProof
	}
	var enc [VRFProofLen]byte
	copy(enc[:], b)
	var p schnorrkel.VrfProof
	if err := p.Decode(enc); err != nil {
		return nil, ErrInvalidVRFProof
	}
	return &VRFProof{
		proof: enc,
	}, nil
}

// Bytes returns the 64-byte encoding of the VRF proof.
func (p *VRFProof) Bytes() [VRFProofLen]byte {
	return p.proof
}

// SignVRF computes a VRF output and proof for message under priv,
// domain-separated by context.
func SignVRF(priv *PrivateKey, context, message []byte) (*VRFOutput, *VRFProof, error) {
	t := merlin.NewTranscript(string(context))
	t.AppendMessage([]byte("message"), message)

	inout, proof, err := priv.secretKey().VrfSign(t)
	if err != nil {
		return nil, nil, ErrVRFSignFailed
	}
	return &VRFOutput{
		out: inout.Output().Encode(),
	}, &VRFProof{
		proof: proof.Encode(),
	}, nil
}

// VerifyVRF reports whether proof certifies that out is the correct VRF
// output for message under pub and context.
func VerifyVRF(pub *PublicKey, context, message []byte, out *VRFOutput, proof *VRFProof) bool {
	var so schnorrkel.VrfOutput
	if err := so.Decode(out.out); err != nil {
		return false
	}
	var sp schnorrkel.VrfProof
	if err := sp.Decode(proof.proof); err != nil {
		return false
	}

	t := merlin.NewTranscript(string(context))
	t.AppendMessage([]byte("message"), message)

	ok, err := pub.schnorrkelKey().VrfVerify(t, &so, &sp)
	if err != nil {
		return false
	}
	return ok
}

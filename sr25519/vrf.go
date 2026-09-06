package sr25519

import (
	"github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// How a (context, message) pair becomes the Merlin transcript the VRF
// operates on is this package's own choice: schnorrkel takes an arbitrary
// transcript and leaves its construction to the caller. Chains that use
// this VRF build theirs from protocol material (block number, epoch
// randomness), so an output from here cross-verifies only against this
// package, not against a chain's own VRF.

// VRFOutput is the VRF's output point: the value a caller derives
// randomness from. It is deterministic in the key and the transcript, so
// the same signer over the same input always produces it.
type VRFOutput struct {
	out [VRFOutputLen]byte
}

// VRFProof is what convinces a verifier that a VRFOutput really is the
// one this key produces for that input. Without it an output is just 32
// bytes anyone could have chosen.
type VRFProof struct {
	proof [VRFProofLen]byte
}

// VRFOutputFromBytes parses a VRF output point.
func VRFOutputFromBytes(b []byte) (*VRFOutput, error) {
	var enc [VRFOutputLen]byte

	if len(b) != VRFOutputLen {
		return nil, ErrInvalidVRFOutput
	}

	copy(enc[:], b)
	if _, err := schnorrkel.NewOutput(enc); err != nil {
		return nil, ErrInvalidVRFOutput
	}

	return &VRFOutput{
		out: enc,
	}, nil
}

// VRFProofFromBytes parses a VRF proof.
func VRFProofFromBytes(b []byte) (*VRFProof, error) {
	var (
		enc [VRFProofLen]byte
		p   schnorrkel.VrfProof
	)

	if len(b) != VRFProofLen {
		return nil, ErrInvalidVRFProof
	}

	copy(enc[:], b)
	if err := p.Decode(enc); err != nil {
		return nil, ErrInvalidVRFProof
	}

	return &VRFProof{
		proof: enc,
	}, nil
}

// Bytes returns the output point, as a copy.
func (o *VRFOutput) Bytes() [VRFOutputLen]byte {
	return o.out
}

// Equal reports whether x is the same output. It is nil-safe.
func (o *VRFOutput) Equal(x *VRFOutput) bool {
	if x == nil {
		return false
	}
	return o.out == x.out
}

// IsZero catches a `var o VRFOutput`; no constructor returns one.
func (o *VRFOutput) IsZero() bool {
	return o == nil || *o == VRFOutput{}
}

// String returns the output as lowercase hex.
func (o *VRFOutput) String() string {
	return encoding.Hex.Encode(o.out[:])
}

// Bytes returns the proof, as a copy.
func (p *VRFProof) Bytes() [VRFProofLen]byte {
	return p.proof
}

// Equal reports whether x is the same proof. It is nil-safe.
func (p *VRFProof) Equal(x *VRFProof) bool {
	if x == nil {
		return false
	}
	return p.proof == x.proof
}

// IsZero catches a `var p VRFProof`; no constructor returns one.
func (p *VRFProof) IsZero() bool {
	return p == nil || *p == VRFProof{}
}

// String returns the proof as lowercase hex.
func (p *VRFProof) String() string {
	return encoding.Hex.Encode(p.proof[:])
}

// SignVRF computes a VRF output and proof for msg under k, separated by ctx.
func SignVRF(k *PrivateKey, ctx, msg []byte) (*VRFOutput, *VRFProof, error) {
	if k == nil {
		return nil, nil, ErrInvalidPrivateKey
	}

	t := merlin.NewTranscript(string(ctx))
	t.AppendMessage([]byte("message"), msg)

	inout, proof, err := k.secretKey().VrfSign(t)
	if err != nil {
		return nil, nil, ErrVRFSignFailed
	}

	return &VRFOutput{
		out: inout.Output().Encode(),
	}, &VRFProof{
		proof: proof.Encode(),
	}, nil
}

// VerifyVRF reports whether proof certifies out as the VRF output for msg
// under k and ctx.
func VerifyVRF(k *PublicKey, ctx, msg []byte, out *VRFOutput, proof *VRFProof) bool {
	var (
		so schnorrkel.VrfOutput
		sp schnorrkel.VrfProof
	)

	if k == nil || out == nil || proof == nil {
		return false
	}
	if err := so.Decode(out.out); err != nil {
		return false
	}
	if err := sp.Decode(proof.proof); err != nil {
		return false
	}

	t := merlin.NewTranscript(string(ctx))
	t.AppendMessage([]byte("message"), msg)

	ok, err := k.schnorrkelKey().VrfVerify(t, &so, &sp)
	return err == nil && ok
}

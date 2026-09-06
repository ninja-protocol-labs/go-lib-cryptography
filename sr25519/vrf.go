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

type VRFOutput struct {
	out [VRFOutputLen]byte
}

type VRFProof struct {
	proof [VRFProofLen]byte
}

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

func (o *VRFOutput) Bytes() [VRFOutputLen]byte {
	return o.out
}

func (o *VRFOutput) Equal(x *VRFOutput) bool {
	if x == nil {
		return false
	}
	return o.out == x.out
}

func (o *VRFOutput) IsZero() bool {
	return o == nil || *o == VRFOutput{}
}

func (o *VRFOutput) String() string {
	return encoding.Hex.Encode(o.out[:])
}

func (p *VRFProof) Bytes() [VRFProofLen]byte {
	return p.proof
}

func (p *VRFProof) Equal(x *VRFProof) bool {
	if x == nil {
		return false
	}
	return p.proof == x.proof
}

func (p *VRFProof) IsZero() bool {
	return p == nil || *p == VRFProof{}
}

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

/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package threshold

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	. "privacy-perserving-audit/common"
	. "privacy-perserving-audit/dory"
	"privacy-perserving-audit/tag"
	"sync"
	"sync/atomic"

	math "github.com/IBM/mathlib"
)

var (
	curve  = math.Curves[1]
	lambda = curve.FieldBytes
)

type PrivateKey math.Zr

func (key PrivateKey) locatePK(ring Ring) (PublicKey, int) {
	sk := math.Zr(key)
	myPK := curve.GenG1.Mul(&sk)
	for i := 0; i < len(ring); i++ {
		if ring[i].Equals(myPK) {
			return PublicKey(*myPK), i
		}
	}

	panic("PK not found within ring")
}

type PublicKey math.G1

type Ring G1v

func (r Ring) Neg() Ring {
	return Ring(G1v(r).Neg())
}

func (r Ring) Add(x G1v) G1v {
	return G1v(r).Add(x)
}

func (r Ring) InnerProd(g2v G2v) *math.Gt {
	return G1v(r).InnerProd(g2v)
}

type PublicParams struct {
	PreProcessedParams
	DoryParams []PP
}

type PreProcessedParams struct {
	digest    []byte
	A0Inverse *math.Gt
	D         *math.Gt
	Γ2        *math.G2
	H1        G1v
}

func (ppp PreProcessedParams) computeDigest(doryParams []PP) []byte {
	h := sha256.New()
	h.Write(ppp.D.Bytes())
	h.Write(ppp.A0Inverse.Bytes())
	h.Write(ppp.Γ2.Bytes())
	h.Write(ppp.H1.Bytes())
	h.Write(doryParams[len(doryParams)-1].Digest(nil))
	return h.Sum(nil)
}

func ComputePreProcessedParams(doryParams []PP, ring Ring) PreProcessedParams {
	pp := doryParams[0]
	A0 := ring.InnerProd(pp.Γ2)
	A0.Inverse()
	H1 := G1v{H()}.Duplicate(len(ring))
	D := H1.InnerProd(pp.Γ2)
	Γ2 := pp.Γ2.Sum()

	ppp := PreProcessedParams{
		Γ2:        Γ2,
		A0Inverse: A0,
		D:         D,
		H1:        H1,
	}

	ppp.digest = ppp.computeDigest(doryParams)
	return ppp
}

func KeyGen() (PublicKey, PrivateKey) {
	sk := curve.NewRandomZr(rand.Reader)
	return PublicKey(*curve.GenG1.Mul(sk)), PrivateKey(*sk)
}

type RingSignature struct {
	TagProof      tag.Proof
	TagCommitment *math.G1
	TagValue      *math.G1
	DoryProof1    Proof
	DoryProof2    Proof
	B             *math.Gt
	Z             *math.Zr
	Y             *math.G1
}

func VerifyThresholdSignatures(pp PublicParams, msg, prefix []byte, signatures ...RingSignature) error {
	tags := make(map[string]struct{})
	for _, σ := range signatures {
		tags[string(σ.TagValue.Bytes())] = struct{}{}
	}

	if len(tags) != len(signatures) {
		return fmt.Errorf("signature set was signed by %d out of %d distinct signers", len(tags), len(signatures))
	}

	var wg sync.WaitGroup
	wg.Add(len(signatures))

	atomicErr := atomic.Value{}

	for _, σ := range signatures {
		go func(σ RingSignature) {
			defer wg.Done()

			err := σ.Verify(pp, msg, prefix)
			if err != nil {
				atomicErr.Store(err)
			}

		}(σ)
	}

	wg.Wait()

	if atomicErr.Load() == nil {
		return nil
	}

	return atomicErr.Load().(error)
}

func (rs RingSignature) Bytes() []byte {
	bytes, err := asn1.Marshal(SerializedSignature{
		TagValue:      rs.TagValue.Bytes(),
		TagCommitment: rs.TagCommitment.Bytes(),
		TagProof:      rs.TagProof.Bytes(),
		B:             rs.B.Bytes(),
		Y:             rs.Y.Bytes(),
		Z:             rs.Z.Bytes(),
		DoryProof1:    rs.DoryProof1.Bytes(),
		DoryProof2:    rs.DoryProof2.Bytes(),
	})

	if err != nil {
		panic(err)
	}

	return bytes
}

type SerializedSignature struct {
	TagProof      []byte
	TagCommitment []byte
	TagValue      []byte
	DoryProof1    []byte
	DoryProof2    []byte
	B             []byte
	Z             []byte
	Y             []byte
}

func (rs RingSignature) Verify(pp PublicParams, m, prefix []byte) error {
	A := e(rs.TagCommitment, pp.Γ2)
	A.Mul(pp.A0Inverse)

	h1zByY := H().Mul(rs.Z)
	h1zByY.Sub(rs.Y)
	C := e(h1zByY, curve.GenG2)

	h := hashToZr(A.Bytes(), rs.Y.Bytes(), pp.digest)
	E := e(H().Mul(h), curve.GenG2)

	var wg sync.WaitGroup
	wg.Add(2)

	atomicErr := atomic.Value{}

	go func() {
		defer wg.Done()

		if err := VerifyReduce(pp.DoryParams, Commitment{
			C:  C,
			D1: A,
			D2: rs.B,
		}, rs.DoryProof1); err != nil {
			atomicErr.Store(fmt.Errorf("first Dory proof invalid"))
		}
	}()

	go func() {
		defer wg.Done()

		if err := VerifyReduce(pp.DoryParams, Commitment{
			C:  E,
			D1: pp.D,
			D2: rs.B,
		}, rs.DoryProof2); err != nil {
			atomicErr.Store(fmt.Errorf("second Dory proof invalid"))
		}
	}()

	if err := rs.TagProof.Verify(rs.TagValue, rs.TagCommitment, prefix, m, rs.DoryProof1.Digest(), rs.DoryProof2.Digest()); err != nil {
		atomicErr.Store(fmt.Errorf("tag proof invalid"))
	}

	wg.Wait()

	if atomicErr.Load() == nil {
		return nil
	}

	return atomicErr.Load().(error)
}

func (key PrivateKey) RingProof(pp PublicParams, ring Ring, r *math.Zr, com *math.G1) RingSignature {
	n := len(ring)

	// Locally load public params
	dpp := pp.DoryParams[0]
	H1 := pp.H1
	D := pp.D
	Γ2 := pp.Γ2
	A0Inverse := pp.A0Inverse

	A := e(com, Γ2)
	A.Mul(A0Inverse)

	y := curve.NewRandomZr(rand.Reader)

	c := make([]*math.Zr, n-1)
	for i := 0; i < len(c); i++ {
		c[i] = curve.NewRandomZr(rand.Reader)
	}

	_, pkIndex := key.locatePK(ring)
	Y := computeY(y, c, com, ring, pkIndex)

	h := hashToZr(A.Bytes(), Y.Bytes(), pp.digest)

	cj := h.Plus(negZr(sumZr(c...)))
	cj.Mod(curve.GroupOrder)

	z := y.Plus(cj.Mul(r))
	z.Mod(curve.GroupOrder)

	c = embedInVec(c, cj, pkIndex)

	cSum := sumZr(c...)
	if !cSum.Equals(h) {
		panic("sum of c isn't h")
	}

	G2c := G2v{curve.GenG2}.Duplicate(n).Mulv(c)

	h1zByY := H().Mul(z)
	h1zByY.Sub(Y)
	C := e(h1zByY, curve.GenG2)

	E := e(H().Mul(h), curve.GenG2)
	B := dpp.Γ1.InnerProd(G2c)

	cmt1 := Commitment{
		C:  C,
		D1: A,
		D2: B,
	}

	w1 := Witness{
		V1: G1v(ring).Neg().Add(G1v{com}.Duplicate(n)),
		V2: G2c,
	}

	cmt2 := Commitment{
		C:  E,
		D1: D,
		D2: B,
	}

	w2 := Witness{
		V1: H1,
		V2: G2c,
	}

	var π1 Proof

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		π1 = Reduce(pp.DoryParams, w1, cmt1)
	}()

	π2 := Reduce(pp.DoryParams, w2, cmt2)

	wg.Wait()

	return RingSignature{
		TagCommitment: com,
		DoryProof1:    π1,
		DoryProof2:    π2,
		Z:             z,
		Y:             Y,
		B:             B,
	}
}

func (key PrivateKey) PreProcessRingProof(pp PublicParams, ring Ring) (r *math.Zr, σ RingSignature) {
	sk := math.Zr(key)
	w, c := tag.Commit(&sk)

	r = &w.R
	σ = key.RingProof(pp, ring, r, c)

	return
}

func (key PrivateKey) AppendTagProof(σ *RingSignature, r *math.Zr, m []byte, prefix []byte) {
	sk := math.Zr(key)

	πt := tag.NewProof(prefix, &sk, &tag.Witness{R: *r}, m, σ.DoryProof1.Digest(), σ.DoryProof2.Digest())
	t := tag.Tag(&sk, prefix)

	σ.TagValue = t
	σ.TagProof = πt
}

func (key PrivateKey) Sign(pp PublicParams, m []byte, prefix []byte, ring Ring) RingSignature {
	sk := math.Zr(key)
	r, com := tag.Commit(&sk)

	σ := key.RingProof(pp, ring, &r.R, com)

	πt := tag.NewProof(prefix, &sk, r, m, σ.DoryProof1.Digest(), σ.DoryProof2.Digest())
	t := tag.Tag(&sk, prefix)

	σ.TagValue = t
	σ.TagProof = πt

	return σ
}

func negZr(x *math.Zr) *math.Zr {
	zero := curve.NewZrFromInt(0)
	return curve.ModSub(zero, x, curve.GroupOrder)
}

func sumZr(in ...*math.Zr) *math.Zr {
	sum := in[0].Copy()
	for i := 1; i < len(in); i++ {
		sum = sum.Plus(in[i])
	}

	sum.Mod(curve.GroupOrder)
	return sum
}

func embedInVec(a []*math.Zr, element *math.Zr, index int) []*math.Zr {
	res := make([]*math.Zr, len(a)+1)

	var current int
	for i := 0; i < len(res); i++ {
		if i == index {
			res[i] = element
		} else {
			res[i] = a[current]
			current++
		}
	}

	return res
}

func computeY(y *math.Zr, c []*math.Zr, com *math.G1, ring Ring, skip int) *math.G1 {
	res := H().Mul(y)
	var cIndex int
	for i := 0; i < len(ring); i++ {
		if i == skip {
			continue
		}
		x := ring[i].Copy()
		x.Sub(com)
		res.Add(x.Mul(c[cIndex]))
		cIndex++
	}

	return res
}

func e(g1 *math.G1, g2 *math.G2) *math.Gt {
	gt := curve.Pairing(g2, g1)
	return curve.FExp(gt)
}

func hashToZr(in ...[]byte) *math.Zr {
	h := sha256.New()
	for _, bytes := range in {
		h.Write(bytes)
	}
	digest := h.Sum(nil)
	return FieldElementFromBytes(digest)
}

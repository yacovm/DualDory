/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dory

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	. "privacy-perserving-audit/common"

	math "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

var (
	c      = math.Curves[1]
	lambda = c.FieldBytes
)

type Proof struct {
	Step1Elements              []ReduceProverStep1Elements
	Step2Elements              []ReduceProverStep2Elements
	ScalarProductProofElements ScalarProductProofElements
	digest                     []byte
}

type RawProof struct {
	Step1Elements              [][][]byte
	Step2Elements              [][][]byte
	ScalarProductProofElements []byte
}

func (p Proof) Digest() []byte {
	if len(p.digest) == 0 {
		p.digest = sha256Digest([][]byte{p.Bytes()})
	}

	return p.digest
}

func (p Proof) Bytes() []byte {
	rp := RawProof{
		ScalarProductProofElements: p.ScalarProductProofElements.Bytes(),
	}

	for _, e := range p.Step1Elements {
		rp.Step1Elements = append(rp.Step1Elements, e.Bytes())
	}

	for _, e := range p.Step2Elements {
		rp.Step2Elements = append(rp.Step2Elements, e.Bytes())
	}

	bytes, err := asn1.Marshal(rp)
	if err != nil {
		panic(err)
	}
	return bytes

}

type Witness struct {
	V1 G1v
	V2 G2v
}

type Commitment struct {
	C, D1, D2 *math.Gt
}

func Commit(v1 G1v, v2 G2v, pp PP) (Commitment, Witness) {
	// Prepare non-blinding part
	D1 := v1.InnerProd(pp.Γ2)
	D2 := pp.Γ1.InnerProd(v2)
	C := v1.InnerProd(v2)

	return Commitment{
			D1: D1,
			D2: D2,
			C:  C,
		}, Witness{
			V1: v1,
			V2: v2,
		}
}

type PP struct {
	digest []byte
	ReducePP
	Γ1 G1v
	Γ2 G2v
	χ  *math.Gt
}

type ReducePP struct {
	Γ1Prime G1v
	Γ2Prime G2v
	Δ1R     *math.Gt
	Δ1L     *math.Gt
	Δ2R     *math.Gt
	Δ2L     *math.Gt
}

func (rpp ReducePP) Digest() []byte {
	h := sha256.New()
	h.Write(rpp.Γ1Prime.Bytes())
	h.Write(rpp.Γ2Prime.Bytes())
	h.Write(rpp.Δ1R.Bytes())
	h.Write(rpp.Δ1L.Bytes())
	h.Write(rpp.Δ2R.Bytes())
	h.Write(rpp.Δ2L.Bytes())
	return h.Sum(nil)
}

type ScalarProductProofElements struct {
	PP *PP
	E1 G1v
	E2 G2v
}

type RawScalarProductProofElements struct {
	P1, P2 []byte
	E1, E2 []byte
}

func (sppe ScalarProductProofElements) Bytes() []byte {
	bytes, err := asn1.Marshal(RawScalarProductProofElements{
		E1: sppe.E1.Bytes(),
		E2: sppe.E2.Bytes(),
	})

	if err != nil {
		panic(err)
	}

	return bytes
}

func (sppe ScalarProductProofElements) Verify(cmt Commitment) error {
	C, D1, D2 := cmt.C, cmt.D1, cmt.D2
	d := randomFE()
	dInv := inverse(d)

	leftEq := e(addG1(sppe.E1[0], sppe.PP.Γ1[0].Mul(d)),
		addG2(sppe.E2[0], sppe.PP.Γ2[0].Mul(inverse(d))))

	rightEq := mulGt(sppe.PP.χ, C, D2.Exp(d), D1.Exp(dInv))

	if leftEq.Equals(rightEq) {
		return nil
	}

	return fmt.Errorf("proof invalid")
}

func NewPublicParams(n int) PP {
	pp := PP{
		Γ1: randomG1Vector(n),
		Γ2: randomG2Vector(n),
	}

	pp.χ = pp.Γ1.InnerProd(pp.Γ2)
	pp.ReducePP = pp.reducePP(n)

	pp.digest = pp.Digest(nil)

	return pp
}

func GeneratePublicParams(n int) []PP {
	var res []PP

	pp := NewPublicParams(n)

	for n > 0 {
		res = append(res, pp)
		if n/2 == 0 {
			break
		}
		pp = pp.NewPublicParams(n / 2)
		n /= 2
	}

	return res
}

func (pp PP) NewPublicParams(n int) PP {
	if len(pp.Γ1) != 2*n || len(pp.Γ2) != 2*n {
		panic("recursive public parameters should be twice as the public parameters it is derived from")
	}
	pp2 := PP{
		Γ1: pp.Γ1Prime,
		Γ2: pp.Γ2Prime,
	}

	pp2.χ = pp2.Γ1.InnerProd(pp2.Γ2)
	pp2.ReducePP = pp2.reducePP(n)

	pp2.digest = pp2.Digest(pp.digest)

	return pp2

}

func (pp PP) Digest(prevDigest []byte) []byte {
	if len(pp.digest) > 0 {
		return pp.digest
	}
	h := sha256.New()

	if len(prevDigest) > 0 {
		h.Write(prevDigest)
	}

	if len(pp.Γ1) != 1 && len(pp.Γ2) != 1 {
		h.Write(pp.ReducePP.Digest())
	}

	h.Write(pp.χ.Bytes())
	h.Write(pp.Γ1.Bytes())
	h.Write(pp.Γ2.Bytes())
	return h.Sum(nil)
}

func (pp PP) reducePP(n int) ReducePP {
	if n == 1 {
		return ReducePP{}
	}
	m := n / 2

	Γ1L := pp.Γ1[:m]
	Γ1R := pp.Γ1[m:]
	Γ2L := pp.Γ2[:m]
	Γ2R := pp.Γ2[m:]

	Γ1Prime := randomG1Vector(m)
	Γ2Prime := randomG2Vector(m)
	Δ1L := Γ1L.InnerProd(Γ2Prime)
	Δ1R := Γ1R.InnerProd(Γ2Prime)
	Δ2L := Γ1Prime.InnerProd(Γ2L)
	Δ2R := Γ1Prime.InnerProd(Γ2R)

	return ReducePP{
		Γ1Prime: Γ1Prime,
		Γ2Prime: Γ2Prime,
		Δ1L:     Δ1L,
		Δ1R:     Δ1R,
		Δ2R:     Δ2R,
		Δ2L:     Δ2L,
	}
}

type ScalarProductProofStep1Elements struct {
	C, D1, D2 *math.Gt
}

func ScalarProductProof(pp PP, w Witness) ScalarProductProofElements {
	E1 := w.V1
	E2 := w.V2

	return ScalarProductProofElements{
		PP: &pp,
		E1: E1,
		E2: E2,
	}
}

func VerifyReduce(pps []PP, commitment Commitment, proof Proof) error {
	return verifyReduce(pps, commitment, proof.Step1Elements, proof.Step2Elements, proof.ScalarProductProofElements)
}

func verifyReduce(pps []PP, commitment Commitment, fromProver1 []ReduceProverStep1Elements, fromProver2 []ReduceProverStep2Elements, finalProof ScalarProductProofElements) error {
	if len(pps) == 1 {
		return finalProof.Verify(commitment)
	}

	pp := pps[0]

	step1Elements := ReduceProverStep1Elements{
		ppDigest: pp.digest,
		C:        commitment.C,
		D1:       commitment.D1,
		D2:       commitment.D2,
		D1L:      fromProver1[0].D1L,
		D1R:      fromProver1[0].D1R,
		D2L:      fromProver1[0].D2L,
		D2R:      fromProver1[0].D2R,
	}

	β := step1Elements.RO()

	step2Elements := ReduceProverStep2Elements{
		ReduceProverStep1ElementsDigest: step1Elements.digest,
		Cminus:                          fromProver2[0].Cminus,
		Cplus:                           fromProver2[0].Cplus,
	}
	α := step2Elements.RO()

	Cplus := fromProver2[0].Cplus
	Cminus := fromProver2[0].Cminus
	inverse_α := inverse(α)
	inverse_β := inverse(β)
	D1L := step1Elements.D1L
	D1R := step1Elements.D1R
	D2L := step1Elements.D2L
	D2R := step1Elements.D2R
	Δ1L := pp.Δ1L
	Δ1R := pp.Δ1R
	Δ2L := pp.Δ2L
	Δ2R := pp.Δ2R

	Cprime := mulGt(commitment.C, pp.χ, commitment.D2.Exp(β), commitment.D1.Exp(inverse_β), Cplus.Exp(α), Cminus.Exp(inverse_α))
	D1prime := mulGt(D1L.Exp(α), D1R, Δ1L.Exp(α).Exp(β), Δ1R.Exp(β))
	D2prime := mulGt(D2L.Exp(inverse_α), D2R, Δ2L.Exp(inverse_α).Exp(inverse_β), Δ2R.Exp(inverse_β))

	nextCommitment := Commitment{
		C:  Cprime,
		D1: D1prime,
		D2: D2prime,
	}

	return verifyReduce(pps[1:], nextCommitment, fromProver1[1:], fromProver2[1:], finalProof)

}

func Reduce(pps []PP, w Witness, commitment Commitment) Proof {
	a, b, c := reduce(pps, w, commitment)
	return Proof{
		Step1Elements:              a,
		Step2Elements:              b,
		ScalarProductProofElements: c,
	}
}

func reduce(pps []PP, w Witness, commitment Commitment) ([]ReduceProverStep1Elements, []ReduceProverStep2Elements, ScalarProductProofElements) {
	pp := pps[0]
	m := len(pp.Γ1) / 2

	Γ1Prime := pp.Γ1Prime
	Γ2Prime := pp.Γ2Prime
	Δ1L := pp.Δ1L
	Δ1R := pp.Δ1R
	Δ2L := pp.Δ2L
	Δ2R := pp.Δ2R

	// P:
	v1L := w.V1[:m]
	v1R := w.V1[m:]
	v2L := w.V2[:m]
	v2R := w.V2[m:]

	// P --> V:
	D1L := v1L.InnerProd(Γ2Prime)
	D1R := v1R.InnerProd(Γ2Prime)
	D2L := Γ1Prime.InnerProd(v2L)
	D2R := Γ1Prime.InnerProd(v2R)

	// V --> P:
	step1Elements := ReduceProverStep1Elements{
		ppDigest: pp.digest,
		C:        commitment.C,
		D1:       commitment.D1,
		D2:       commitment.D2,
		D1L:      D1L,
		D1R:      D1R,
		D2L:      D2L,
		D2R:      D2R,
	}

	β := step1Elements.RO()
	inverse_β := inverse(β)

	// P:
	v1 := w.V1.Add(pp.Γ1.Mul(β))
	v2 := w.V2.Add(pp.Γ2.Mul(inverse_β))

	v1L = v1[:m]
	v1R = v1[m:]
	v2L = v2[:m]
	v2R = v2[m:]

	// P --> V:
	Cplus := v1L.InnerProd(v2R)
	Cminus := v1R.InnerProd(v2L)

	step2Elements := ReduceProverStep2Elements{
		ReduceProverStep1ElementsDigest: step1Elements.digest,
		Cminus:                          Cminus,
		Cplus:                           Cplus,
	}
	α := step2Elements.RO()

	inverse_α := inverse(α)

	v1prime := v1L.Mul(α).Add(v1R)
	v2prime := v2L.Mul(inverse_α).Add(v2R)

	nextWitness := Witness{
		V1: v1prime,
		V2: v2prime,
	}

	Cprime := mulGt(commitment.C, pp.χ, commitment.D2.Exp(β), commitment.D1.Exp(inverse_β), Cplus.Exp(α), Cminus.Exp(inverse_α))
	D1prime := mulGt(D1L.Exp(α), D1R, Δ1L.Exp(α).Exp(β), Δ1R.Exp(β))
	D2prime := mulGt(D2L.Exp(inverse_α), D2R, Δ2L.Exp(inverse_α).Exp(inverse_β), Δ2R.Exp(inverse_β))

	nextCommitment := Commitment{
		C:  Cprime,
		D1: D1prime,
		D2: D2prime,
	}

	if m == 1 {
		return []ReduceProverStep1Elements{step1Elements}, []ReduceProverStep2Elements{step2Elements}, ScalarProductProof(pps[1], nextWitness)
	}

	step1Aggregated, step2Aggregated, scalarProductProof := reduce(pps[1:], nextWitness, nextCommitment)

	var res1 []ReduceProverStep1Elements
	var res2 []ReduceProverStep2Elements

	res1 = append([]ReduceProverStep1Elements{step1Elements}, step1Aggregated...)
	res2 = append([]ReduceProverStep2Elements{step2Elements}, step2Aggregated...)

	return res1, res2, scalarProductProof
}

type ReduceProverStep1Elements struct {
	ppDigest           []byte
	digest             []byte
	D1L, D1R, D2L, D2R *math.Gt
	C, D1, D2          *math.Gt
}

func (x ReduceProverStep1Elements) Bytes() [][]byte {
	var bytes [][]byte
	bytes = append(bytes, x.ppDigest)
	bytes = append(bytes, x.D1L.Bytes())
	bytes = append(bytes, x.D1R.Bytes())
	bytes = append(bytes, x.D2L.Bytes())
	bytes = append(bytes, x.D2R.Bytes())
	bytes = append(bytes, x.C.Bytes())
	bytes = append(bytes, x.D1.Bytes())
	bytes = append(bytes, x.D2.Bytes())

	return bytes
}

func (x *ReduceProverStep1Elements) RO() *math.Zr {
	x.digest = sha256Digest(x.Bytes())
	return FieldElementFromBytes(x.digest)
}

type ReduceProverStep2Elements struct {
	ReduceProverStep1ElementsDigest []byte
	Cplus, Cminus                   *math.Gt
}

func (x ReduceProverStep2Elements) Bytes() [][]byte {
	if len(x.ReduceProverStep1ElementsDigest) == 0 {
		panic("un-initialized ReduceProverStep1ElementsDigest")
	}
	var bytes [][]byte
	bytes = append(bytes, x.Cplus.Bytes())
	bytes = append(bytes, x.Cminus.Bytes())
	bytes = append(bytes, x.ReduceProverStep1ElementsDigest)

	return bytes
}

func (x ReduceProverStep2Elements) RO() *math.Zr {
	return FieldElementFromBytes(sha256Digest(x.Bytes()))
}

func e(g1 *math.G1, g2 *math.G2) *math.Gt {
	gt := c.Pairing(g2, g1)
	return c.FExp(gt)
}

func mulGt(xs ...*math.Gt) *math.Gt {
	prod, err := c.NewGtFromBytes(xs[0].Bytes())
	if err != nil {
		panic(err)
	}

	for i := 1; i < len(xs); i++ {
		prod.Mul(xs[i])
	}

	return prod
}

func addG1(xs ...*math.G1) *math.G1 {
	z := xs[0].Copy()
	for i := 1; i < len(xs); i++ {
		z.Add(xs[i])
	}

	return z
}

func addG2(xs ...*math.G2) *math.G2 {
	z := xs[0].Copy()
	for i := 1; i < len(xs); i++ {
		z.Add(xs[i])
	}

	return z
}

func randomG1Vector(n int) G1v {
	v := make(G1v, n)
	for i := 0; i < n; i++ {
		v[i] = psuedoRandomG1(n, i)
	}
	return v
}

func randomG2Vector(n int) G2v {
	v := make(G2v, n)
	for i := 0; i < n; i++ {
		v[i] = psuedoRandomG2(n, i)
	}
	return v
}

func randomFE() *math.Zr {
	return c.NewRandomZr(rand.Reader)
}

func randomBytes() []byte {
	buff := make([]byte, lambda)
	_, err := rand.Read(buff)
	if err != nil {
		panic(err)
	}

	return buff
}

func inverse(x *math.Zr) *math.Zr {
	xInv := x.Copy()
	xInv.InvModP(c.GroupOrder)
	return xInv
}

func sha256Digest(in [][]byte) []byte {
	h := sha256.New()
	for _, d := range in {
		h.Write(d)
	}
	digest := h.Sum(nil)
	return digest
}

func psuedoRandomG1(n int, i int) *math.G1 {
	return c.HashToG1(sha256Digest([][]byte{[]byte("Dory"), {byte(n), byte(n >> 8)}, {byte(i), byte(i >> 8)}}))
}

func psuedoRandomG2(n int, i int) *math.G2 {
	g2, err := bn254.HashToCurveG2Svdw(sha256Digest([][]byte{[]byte("Dory"), {byte(n), byte(n >> 8)}, {byte(i), byte(i >> 8)}}), []byte{})
	if err != nil {
		panic(err)
	}

	bytes := g2.Bytes()
	g, err := c.NewG2FromBytes(bytes[:])
	if err != nil {
		panic(err)
	}

	return g
}

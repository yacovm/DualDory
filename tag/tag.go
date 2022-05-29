/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tag

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	. "privacy-perserving-audit/common"

	math "github.com/IBM/mathlib"
)

var (
	curve  = math.Curves[1]
	lambda = curve.FieldBytes
)

type Proof struct {
	A, B *math.G1
	a, b *math.Zr
}

type Witness struct {
	R math.Zr
}

func Commit(sk *math.Zr) (*Witness, *math.G1) {
	w := &Witness{
		R: *curve.NewRandomZr(rand.Reader),
	}

	com := curve.GenG1.Mul(sk)
	com.Add(H().Mul(&w.R))

	return w, com
}

func Tag(sk *math.Zr, prefix []byte) *math.G1 {
	return curve.HashToG1(sha256Digest(prefix)).Mul(sk)
}

func NewProof(prefix []byte, sk *math.Zr, w *Witness, additionalContext ...[]byte) Proof {
	ar, br := curve.NewRandomZr(rand.Reader), curve.NewRandomZr(rand.Reader)

	A := curve.HashToG1(sha256Digest(prefix)).Mul(ar)
	B := curve.GenG1.Mul(ar)
	B.Add(H().Mul(br))

	hashInput := buildHashContext(A, B, additionalContext)
	c := hashToZr(hashInput...)

	a := ar.Plus(sk.Mul(c))
	b := br.Plus(w.R.Mul(c))

	return Proof{
		A: A,
		B: B,
		a: a,
		b: b,
	}
}

func (p Proof) Bytes() []byte {
	bytes, err := asn1.Marshal(RawProof{
		A:  p.A.Bytes(),
		B:  p.B.Bytes(),
		Za: p.a.Bytes(),
		Zb: p.b.Bytes(),
	})
	if err != nil {
		panic(err)
	}
	return bytes
}

type RawProof struct {
	A, B   []byte
	Za, Zb []byte
}

func (p Proof) Verify(tag *math.G1, com *math.G1, prefix []byte, additionalContext ...[]byte) error {
	hashInput := buildHashContext(p.A, p.B, additionalContext)
	c := hashToZr(hashInput...)
	leftEq := curve.HashToG1(sha256Digest(prefix)).Mul(p.a)

	rightEq := tag.Mul(c)
	rightEq.Add(p.A)

	if !leftEq.Equals(rightEq) {
		return fmt.Errorf("tag proof mismatch")
	}

	leftEq = curve.GenG1.Mul(p.a)
	leftEq.Add(H().Mul(p.b))

	rightEq = p.B.Copy()
	rightEq.Add(com.Mul(c))

	if !leftEq.Equals(rightEq) {
		return fmt.Errorf("commitment proof mismatch")
	}

	return nil
}

func buildHashContext(A, B *math.G1, additionalContext [][]byte) [][]byte {
	var hashInput [][]byte
	hashInput = append(hashInput, A.Bytes(), B.Bytes())
	for _, ctx := range additionalContext {
		hashInput = append(hashInput, ctx)
	}
	return hashInput
}

func hashToZr(elements ...[]byte) *math.Zr {
	h := sha256.New()
	for _, e := range elements {
		h.Write(e)
	}
	digest := h.Sum(nil)
	return FieldElementFromBytes(digest)
}

func sha256Digest(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	digest := h.Sum(nil)
	return digest
}

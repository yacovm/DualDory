/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"

	math "github.com/IBM/mathlib"
	common2 "github.com/IBM/mathlib/driver/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var (
	c      = math.Curves[1]
	lambda = c.FieldBytes
	h      = c.HashToG1(sha256Digest("DualDory"))
)

type G1v []*math.G1
type G2v []*math.G2

func (g1v G1v) Add(g1v2 G1v) G1v {
	res := make(G1v, len(g1v))
	for i := 0; i < len(res); i++ {
		res[i] = g1v[i].Copy()
		res[i].Add(g1v2[i])
	}
	return res
}

func (g1v G1v) Neg() G1v {
	zero := c.GenG1.Copy()
	zero.Sub(zero)

	res := make(G1v, len(g1v))
	for i := 0; i < len(g1v); i++ {
		res[i] = zero.Copy()
		res[i].Sub(g1v[i])
	}

	return res
}

func (g1v G1v) Mul(x *math.Zr) G1v {
	res := make(G1v, len(g1v))
	for i := 0; i < len(res); i++ {
		res[i] = g1v[i].Mul(x)
	}
	return res
}

func (g1v G1v) Bytes() []byte {
	bb := bytes.Buffer{}
	for _, g := range g1v {
		bb.Write(g.Bytes())
	}
	return bb.Bytes()
}

func (g1v G1v) Duplicate(n int) G1v {
	if len(g1v) != 1 {
		panic("length should be 1")
	}

	var res G1v
	for i := 0; i < n; i++ {
		res = append(res, g1v[0].Copy())
	}
	return res
}

func (g2v G2v) Mulv(x []*math.Zr) G2v {
	res := make(G2v, len(g2v))
	for i := 0; i < len(res); i++ {
		res[i] = g2v[i].Mul(x[i])
	}
	return res
}

func (g2v G2v) Duplicate(n int) G2v {
	if len(g2v) != 1 {
		panic("length should be 1")
	}

	var res G2v
	for i := 0; i < n; i++ {
		res = append(res, g2v[0].Copy())
	}
	return res
}

func (g2v G2v) Add(g2v2 G2v) G2v {
	res := make(G2v, len(g2v))
	for i := 0; i < len(res); i++ {
		res[i] = g2v[i].Copy()
		res[i].Add(g2v2[i])
	}
	return res
}

func (g2v G2v) Mul(x *math.Zr) G2v {
	res := make(G2v, len(g2v))
	for i := 0; i < len(res); i++ {
		res[i] = g2v[i].Mul(x)
	}
	return res
}

func (g2v G2v) Bytes() []byte {
	bb := bytes.Buffer{}
	for _, g := range g2v {
		bb.Write(g.Bytes())
	}
	return bb.Bytes()
}

func (g2v G2v) Sum() *math.G2 {
	sum := g2v[0].Copy()
	for i := 1; i < len(g2v); i++ {
		sum.Add(g2v[i])
	}
	return sum
}

func (g1v G1v) InnerProd(g2v G2v) *math.Gt {
	if len(g1v) != len(g2v) {
		panic(fmt.Sprintf("length mismatch"))
	}

	if len(g1v) == 0 || len(g2v) == 0 {
		panic("empty vectors")
	}

	if len(g1v) == 1 {
		return e(g1v[0], g2v[0])
	}

	prod := c.Pairing(g2v[0], g1v[0])

	for i := 1; i < len(g2v); i++ {
		x := c.Pairing(g2v[i], g1v[i])
		prod.Mul(x)
	}

	prod = c.FExp(prod)

	return prod
}

func e(g1 *math.G1, g2 *math.G2) *math.Gt {
	gt := c.Pairing(g2, g1)
	return c.FExp(gt)
}

func sha256Digest(in string) []byte {
	h := sha256.New()
	h.Write([]byte(in))
	digest := h.Sum(nil)
	return digest
}

func H() *math.G1 {
	return h.Copy()
}

func FieldElementFromBytes(digest []byte) *math.Zr {
	fe := feFrom256Bits(digest)
	n := new(big.Int)
	n = fe.ToBigIntRegular(n)
	return c.NewZrFromBytes(common2.BigToBytes(n))
}

func feFrom256Bits(bytes []byte) *fr.Element {
	if len(bytes) != 32 {
		panic(fmt.Sprintf("input should be 32 bytes"))
	}
	var z fr.Element
	z[0] = binary.BigEndian.Uint64(bytes[0:8])
	z[1] = binary.BigEndian.Uint64(bytes[8:16])
	z[2] = binary.BigEndian.Uint64(bytes[16:24])
	z[3] = binary.BigEndian.Uint64(bytes[24:32])
	z[3] %= 3486998266802970665

	// if z > q → z -= q
	// note: this is NOT constant time
	if !(z[3] < 3486998266802970665 || (z[3] == 3486998266802970665 && (z[2] < 13281191951274694749 || (z[2] == 13281191951274694749 && (z[1] < 2896914383306846353 || (z[1] == 2896914383306846353 && (z[0] < 4891460686036598785))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 4891460686036598785, 0)
		z[1], b = bits.Sub64(z[1], 2896914383306846353, b)
		z[2], b = bits.Sub64(z[2], 13281191951274694749, b)
		z[3], _ = bits.Sub64(z[3], 3486998266802970665, b)
	}

	return &z
}

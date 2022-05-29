/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dory

import (
	"fmt"
	"privacy-perserving-audit/common"
	"testing"
	"time"

	math "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/assert"
)

func TestScalarProductProof(t *testing.T) {
	PP := NewPublicParams(1)
	v1 := common.G1v{randomG1()}
	v2 := common.G2v{randomG2()}
	cmt, witness := Commit(v1, v2, PP)

	var proofTime time.Duration
	var verificationTime time.Duration
	for i := 0; i < 100; i++ {
		t1 := time.Now()
		proof := ScalarProductProof(PP, witness)
		proofTime += time.Since(t1)

		t1 = time.Now()
		err := proof.Verify(cmt)
		verificationTime += time.Since(t1)
		assert.NoError(t, err)
	}

	fmt.Println(proofTime / 100)
	fmt.Println(verificationTime / 100)
}

func TestInnerProd(t *testing.T) {
	g1a, g1b, g1c := randomG1(), randomG1(), randomG1()
	g2a, g2b, g2c := randomG2(), randomG2(), randomG2()

	expected := mulGt(e(g1a, g2a), e(g1b, g2b), e(g1c, g2c))

	g1 := common.G1v{g1a, g1b, g1c}
	g2 := common.G2v{g2a, g2b, g2c}

	actual := g1.InnerProd(g2)

	assert.True(t, expected.Equals(actual))
}

func TestDoryReduce(t *testing.T) {

	v1 := randomG1Vector(8)
	v2 := randomG2Vector(8)

	pps := GeneratePublicParams(8)

	cmt, witness := Commit(v1, v2, pps[0])

	var proofTime time.Duration
	var verificationTime time.Duration

	for i := 0; i < 100; i++ {
		t1 := time.Now()
		proof := Reduce(pps, witness, cmt)
		proofTime += time.Since(t1)

		assert.Len(t, proof.Step1Elements, 3)
		assert.Len(t, proof.Step2Elements, 3)

		assert.Len(t, pps[0].Γ1, 8)
		assert.Len(t, pps[1].Γ1, 4)
		assert.Len(t, pps[2].Γ1, 2)
		assert.Len(t, pps[3].Γ1, 1)

		assert.Len(t, pps[0].Γ1Prime, 4)
		assert.Len(t, pps[1].Γ1Prime, 2)
		assert.Len(t, pps[2].Γ1Prime, 1)
		assert.Len(t, pps[3].Γ1Prime, 0)

		assert.NotNil(t, proof)

		t1 = time.Now()
		err := VerifyReduce(pps, cmt, proof)
		verificationTime += time.Since(t1)
		assert.NoError(t, err)
	}

	fmt.Println(proofTime / 100)
	fmt.Println(verificationTime / 100)
}

func randomG1() *math.G1 {
	return c.HashToG1(randomBytes())
}

func randomG2() *math.G2 {
	g2, err := bn254.HashToCurveG2Svdw(randomBytes(), []byte{})
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

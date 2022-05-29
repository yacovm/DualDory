/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package threshold

import (
	"crypto/rand"
	"privacy-perserving-audit/dory"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
)

func TestThresholdRingSignature(t *testing.T) {
	pk1, sk1 := KeyGen()
	pk2, sk2 := KeyGen()
	pk3, _ := KeyGen()
	pk4, _ := KeyGen()

	ring := Ring{(*math.G1)(&pk1), (*math.G1)(&pk2), (*math.G1)(&pk3), (*math.G1)(&pk4)}

	pps := dory.GeneratePublicParams(4)
	ppp := ComputePreProcessedParams(pps, ring)

	pp := PublicParams{
		DoryParams:         pps,
		PreProcessedParams: ppp,
	}

	msg := make([]byte, 32)
	_, err := rand.Read(msg)
	assert.NoError(t, err)

	prefix := []byte{1, 2, 3}

	σ1 := sk1.Sign(pp, msg, prefix, ring)
	σ2 := sk2.Sign(pp, msg, prefix, ring)

	err = VerifyThresholdSignatures(pp, msg, prefix, σ1, σ2)
	assert.NoError(t, err)

	err = VerifyThresholdSignatures(pp, msg, prefix, σ1, σ1)
	assert.EqualError(t, err, "signature set was signed by 1 out of 2 distinct signers")

}

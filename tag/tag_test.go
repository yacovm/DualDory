/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tag

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTagProof(t *testing.T) {
	sk := curve.NewRandomZr(rand.Reader)
	w, com := Commit(sk)

	prefix := []byte{1, 2, 3}

	tag := Tag(sk, prefix)

	proof := NewProof(prefix, sk, w)
	err := proof.Verify(tag, com, prefix)
	assert.NoError(t, err)

	err = proof.Verify(tag, com, []byte{3, 2, 1})
	assert.EqualError(t, err, "tag proof mismatch")
}

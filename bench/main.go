/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/rand"
	"fmt"
	rand2 "math/rand"
	"privacy-perserving-audit/dory"
	"privacy-perserving-audit/threshold"
	"time"

	math "github.com/IBM/mathlib"
)

func main() {
	pp := make(map[int]int)
	signing := make(map[int]int)
	dualRingDory := make(map[int]int)
	appendProcess := make(map[int]int)
	verification := make(map[int]int)
	sizes := make(map[int]int)
	for n := 2; n <= 1024; n *= 2 {
		averagePP, averageSigning, averageVerification, averageDualRingDory, averageAppend, size := benchmark(n)
		time.Sleep(time.Second)
		sizes[n] = size
		pp[n] = int(averagePP)
		signing[n] = int(averageSigning)
		verification[n] = int(averageVerification)
		dualRingDory[n] = int(averageDualRingDory)
		appendProcess[n] = int(averageAppend)
		fmt.Println(">>>", n, averageSigning, averageVerification)
	}

	fmt.Println("Sizes:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, sizes[n])
	}
	fmt.Println()

	fmt.Println("Pre-processing:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, pp[n])
	}
	fmt.Println()

	fmt.Println("Signing:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, signing[n])
	}
	fmt.Println()

	fmt.Println("dualring+dory:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, dualRingDory[n])
	}
	fmt.Println()

	fmt.Println("Append tag:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, appendProcess[n])
	}
	fmt.Println()

	fmt.Println("Verify:")
	for n := 2; n <= 1024; n *= 2 {
		fmt.Printf("(%d, %d)", n, verification[n])
	}
	fmt.Println()

}

func benchmark(n int) (int64, int64, int64, int64, int64, int) {
	trials := 100

	privateKeys, ring := makeRing(n)
	doryPP := dory.GeneratePublicParams(n)

	var totalPPTime time.Duration

	for i := 0; i < trials; i++ {
		start := time.Now()
		threshold.ComputePreProcessedParams(dory.GeneratePublicParams(n), ring)
		totalPPTime += time.Since(start)
	}

	ppp := threshold.ComputePreProcessedParams(doryPP, ring)
	pp := threshold.PublicParams{
		DoryParams:         doryPP,
		PreProcessedParams: ppp,
	}

	msg := make([]byte, 32)
	_, err := rand.Read(msg)
	if err != nil {
		panic(err)
	}

	prefix := make([]byte, 32)
	_, err = rand.Read(prefix)
	if err != nil {
		panic(err)
	}

	time.Sleep(time.Millisecond * 500)


	signatures := make([]threshold.RingSignature, trials)
	var totalSigningTime time.Duration
	var totalVerificationTime time.Duration
	var totalDualRingDoryTime time.Duration
	var totalAppendTagTime time.Duration

	for i := 0; i < trials; i++ {
		sk := privateKeys[rand2.Intn(len(privateKeys))]
		startSigning := time.Now()
		σ := sk.Sign(pp, msg, prefix, ring)
		// Pre-process digest computation
		σ.DoryProof1.Digest()
		σ.DoryProof2.Digest()
		totalSigningTime += time.Since(startSigning)
		signatures[i] = σ
		time.Sleep(time.Millisecond * 200)

		startVerification := time.Now()
		err := σ.Verify(pp, msg, prefix)
		totalVerificationTime += time.Since(startVerification)
		if err != nil {
			panic(err)
		}

		startDualRingDory := time.Now()
		r, σ := sk.PreProcessRingProof(pp, ring)
		totalDualRingDoryTime += time.Since(startDualRingDory)
		time.Sleep(time.Millisecond * 200)

		startAppend := time.Now()
		sk.AppendTagProof(&σ, r, msg, prefix)
		totalAppendTagTime += time.Since(startAppend)

		time.Sleep(time.Millisecond * 200)

		// This is only for sanity check
		err = σ.Verify(pp, msg, prefix)
		if err != nil {
			panic(err)
		}
	}

	averageSign := totalSigningTime / time.Duration(trials)
	averageVerify := totalVerificationTime / time.Duration(trials)
	averageDualRingDory := totalDualRingDoryTime / time.Duration(trials)
	averageAppend := totalAppendTagTime / time.Duration(trials)
	averagePP := totalPPTime / time.Duration(trials)

	var size int
	for _, σ := range signatures {
		size += len(σ.Bytes())
	}

	return averagePP.Milliseconds(), averageSign.Milliseconds(), averageVerify.Milliseconds(), averageDualRingDory.Milliseconds(), averageAppend.Microseconds(), size / len(signatures)
}

func makeRing(n int) ([]threshold.PrivateKey, threshold.Ring) {
	var privateKeys []threshold.PrivateKey
	var ring threshold.Ring
	for i := 0; i < n; i++ {
		pk, sk := threshold.KeyGen()
		privateKeys = append(privateKeys, sk)
		ring = append(ring, (*math.G1)(&pk))
	}

	return privateKeys, ring
}

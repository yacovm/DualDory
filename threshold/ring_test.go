/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package threshold

import (
	"crypto/rand"
	"fmt"
	math2 "math"
	"privacy-perserving-audit/common"
	"privacy-perserving-audit/dory"
	"strings"
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

type measurement struct {
	n int64
	count int64
}

type measurements []measurement

func (ms measurements) toMap() map[int64]uint32 {
	res := make(map[int64]uint32)
	for _, m := range ms {
		res[m.n] = uint32(m.count)
	}
	return res
}

type stats struct {
	pairingsCoords    strings.Builder
	additionsG1Coords strings.Builder
	additionsG2Coords strings.Builder
	multsG1Coords     strings.Builder
	multsG2Coords     strings.Builder
	multsGtCoords     strings.Builder
	expGtCoords       strings.Builder
	pairingsMeasurements measurements
	additionsG1Measurements measurements
	additionsG2Measurements measurements
	multsG1Measurements measurements
	multsG2Measurements measurements
	multsGtMeasurements measurements
	expGtMeasurements measurements
}

func processStats(n int, stats common.Stats, s *stats) {
	s.recordCoords(n, stats)
	processMeasurements(n, stats, s)
}

func processMeasurements(n int, stats common.Stats, s *stats) {
	s.additionsG1Measurements = append(s.additionsG1Measurements, measurement{n: int64(n), count: int64(stats.AdditionsG1)})
	s.additionsG2Measurements = append(s.additionsG2Measurements, measurement{n: int64(n), count: int64(stats.AdditionsG2)})
	s.multsG1Measurements = append(s.multsG1Measurements, measurement{n: int64(n), count: int64(stats.MultiplicationsG1)})
	s.multsG2Measurements = append(s.multsG2Measurements, measurement{n: int64(n), count: int64(stats.MultiplicationsG2)})
	s.multsGtMeasurements = append(s.multsGtMeasurements, measurement{n: int64(n), count: int64(stats.MultiplicationsGt)})
	s.expGtMeasurements = append(s.expGtMeasurements, measurement{n: int64(n), count: int64(stats.ExponentiationsGt)})
	s.pairingsMeasurements = append(s.pairingsMeasurements, measurement{n: int64(n), count: int64(stats.Pairings)})
}

func (s *stats) recordCoords(n int, stats common.Stats) {
	s.pairingsCoords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.Pairings))
	s.additionsG1Coords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.AdditionsG1))
	s.additionsG2Coords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.AdditionsG2))
	s.multsG1Coords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.MultiplicationsG1))
	s.multsG2Coords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.MultiplicationsG2))
	s.multsGtCoords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.MultiplicationsGt))
	s.expGtCoords.WriteString(fmt.Sprintf("(%d, %d)", n, stats.ExponentiationsGt))

}

func TestMeasureOperations(t *testing.T) {
	var ppMeasurements stats
	var signMeasurements stats
	var verifyMeasurements stats

	for n := 8; n <= 2048; n*= 2 {
		sks, ring := makeRing(n)

		common.CollectStats() // Reset

		pps := dory.GeneratePublicParams(n)
		ppp := ComputePreProcessedParams(pps, ring)

		ppStats := common.CollectStats()
		processStats(n, ppStats, &ppMeasurements)

		pp := PublicParams{
			DoryParams:         pps,
			PreProcessedParams: ppp,
		}

		msg := make([]byte, 32)
		_, err := rand.Read(msg)
		assert.NoError(t, err)

		prefix := []byte{1, 2, 3}


		σ := sks[0].Sign(pp, msg, prefix, ring)

		signStats := common.CollectStats()
		processStats(n, signStats, &signMeasurements)

		err = σ.Verify(pp, msg, prefix)
		assert.NoError(t, err)

		verifyStats := common.CollectStats()
		processStats(n, verifyStats, &verifyMeasurements)
	}

	tableTemplate := `
\begin{tabular}{|*{9}{c|}}\hline
    \diagbox{Algorithm}{Operation}
	&\makebox[2.5em]{$\mathbb{G}_1,+$}&\makebox[2.5em]{$\mathbb{G}_2,+$}&\makebox[2.5em]{$\mathbb{G}_1,*$}
	&\makebox[2.5em]{$\mathbb{G}_2,*$}&\makebox[2.5em]{$\mathbb{G}_t,*$}&\makebox[2.5em]{$\mathbb{G}_t,\string^$}&\makebox[6em]{$\left(\mathbb{G}_1, \mathbb{G}_2\right)\rightarrow \mathbb{G}_t$}\\\hline
	Offline phase &G1OA&G2OA&G1OM&G2OM&GTOM&GTOE&OP\\\hline
	Signing &G1SA&G2SA&G1SM&G2SM&GTSM&GTSE&SP\\\hline
	Verification &G1VA&G2VA&G1VM&G2VM&GTVM&GTVE&VP\\\hline
\end{tabular}`

	table := tableTemplate

	for placeholder, measurement := range map[string]measurements{
		"G1OA": ppMeasurements.additionsG1Measurements,
		"G2OA": ppMeasurements.additionsG2Measurements,
		"G1OM": ppMeasurements.multsG1Measurements,
		"G2OM": ppMeasurements.multsG2Measurements,
		"GTOM": ppMeasurements.multsGtMeasurements,
		"GTOE": ppMeasurements.expGtMeasurements,
		"OP": ppMeasurements.pairingsMeasurements,

		"G1SA": signMeasurements.additionsG1Measurements,
		"G2SA": signMeasurements.additionsG2Measurements,
		"G1SM": signMeasurements.multsG1Measurements,
		"G2SM": signMeasurements.multsG2Measurements,
		"GTSM": signMeasurements.multsGtMeasurements,
		"GTSE": signMeasurements.expGtMeasurements,
		"SP": signMeasurements.pairingsMeasurements,

		"G1VA": verifyMeasurements.additionsG1Measurements,
		"G2VA": verifyMeasurements.additionsG2Measurements,
		"G1VM": verifyMeasurements.multsG1Measurements,
		"G2VM": verifyMeasurements.multsG2Measurements,
		"GTVM": verifyMeasurements.multsGtMeasurements,
		"GTVE": verifyMeasurements.expGtMeasurements,
		"VP": verifyMeasurements.pairingsMeasurements,
	} {
		table = strings.Replace(table, placeholder, fmt.Sprintf("\\footnotesize %s", findCoefficients(measurement.toMap())), 1)
	}

	fmt.Println(table)
}

type coefficients struct {
	a, b, c int64
}

func (c coefficients) f(n int64) uint32 {
	logN := int64(math2.Log2(float64(n)))
	return uint32( c.a * n + c.b *logN + c.c)
}

func findCoefficients(stats map[int64]uint32) string {
	var solution coefficients
	var found bool
	// f = a*N + b*Log(N) + c + d*N*Log(N)
	for a := int64(-100); a < 100; a++ {
		for b := int64(-100); b < 100; b++ {
			for c := int64(-100); c < 100; c++ {
					candidate := coefficients{a: a, b: b, c: c}
					var misses int
					for n := int64(8); n <= 2048; n *= 2 {
						if candidate.f(n) != stats[n] {
							misses++
							continue
						}
					}

					if misses > 0 {
						continue
					}

					if found {
						panic(fmt.Sprintf("found two suitable candidates: %v, %v, %d", candidate, solution, stats))
					}
					solution = candidate
					found = true
			}
		}
	}

	linear := func(n int64) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf("%dN", n)
	}

	log := func(n int64) string {
		if n == 0 {
			return ""
		}
		if n < 0 {
			return fmt.Sprintf("%dLog(N)", n)
		}

		return fmt.Sprintf("+%dLog(N)", n)
	}

	constant := func(n int64) string {
		if n == 0 {
			return ""
		}
		if n < 0 {
			return fmt.Sprintf("%d", n)
		}

		return fmt.Sprintf("+%d", n)
	}

	if found {
		res := fmt.Sprintf("%s%s%s", linear(solution.a), log(solution.b), constant(solution.c))
		if strings.Index(res, "+") == 0 {
			return res[1:]
		}
		return res
	}
	panic(fmt.Sprintf("could not find a coefficient"))
}

func makeRing(n int) ([]PrivateKey, Ring) {
	var privateKeys []PrivateKey
	var ring Ring
	for i := 0; i < n; i++ {
		pk, sk := KeyGen()
		privateKeys = append(privateKeys, sk)
		ring = append(ring, (*math.G1)(&pk))
	}

	return privateKeys, ring
}

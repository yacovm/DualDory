/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"sync/atomic"

	"github.com/IBM/mathlib/driver/gurvy"
)

type Stats struct {
	Pairings          uint32
	AdditionsG1       uint32
	MultiplicationsG1 uint32
	AdditionsG2       uint32
	MultiplicationsG2 uint32
	MultiplicationsGt uint32
	ExponentiationsGt uint32
}

func CollectStats() Stats {
	defer func() {
		atomic.StoreUint32(&gurvy.Pairings, 0)
		atomic.StoreUint32(&gurvy.AdditionsG1, 0)
		atomic.StoreUint32(&gurvy.AdditionsG2, 0)
		atomic.StoreUint32(&gurvy.MultiplicationsG1, 0)
		atomic.StoreUint32(&gurvy.MultiplicationsG2, 0)
		atomic.StoreUint32(&gurvy.ExponentiationsGt, 0)
		atomic.StoreUint32(&gurvy.MultiplicationsGt, 0)
	}()

	return Stats{
		Pairings:          atomic.LoadUint32(&gurvy.Pairings),
		AdditionsG1:       atomic.LoadUint32(&gurvy.AdditionsG1),
		AdditionsG2:       atomic.LoadUint32(&gurvy.AdditionsG2),
		MultiplicationsG1: atomic.LoadUint32(&gurvy.MultiplicationsG1),
		MultiplicationsG2: atomic.LoadUint32(&gurvy.MultiplicationsG2),
		ExponentiationsGt: atomic.LoadUint32(&gurvy.ExponentiationsGt),
		MultiplicationsGt: atomic.LoadUint32(&gurvy.MultiplicationsGt),
	}

}

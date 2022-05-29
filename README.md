DualDory: Logarithmic-verifier linkable ring signatures through preprocessing
===============================================================================

This project contains an implementation of the [DualDory paper](https://DualDory.github.io).

The folder/package structure is as follows:

- `bench`: Contains a `main.go` that benchmarks the paper.
- `common`: Contains common functions used by the rest of the packages.
- `dory`: Implements the non privacy-preserving technique of the [Dory paper](https://eprint.iacr.org/2020/1274.pdf), which is used in a black box manner by the `threshold` package.
- `tag`: Implements the tag proof of the DualDory paper, used by the `threshold` package.
- `threshold`: Implements the ring signature scheme, as well as a threshold ring signature scheme.


How to run the tests? 
------------------------
Run `go test ./...` in the top level folder.


How to build and run the benchmark?
--------------------------------------
From the top level folder, execute:
```
cd bench
go build
./bench
```

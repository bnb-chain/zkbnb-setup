module github.com/bnbchain/zkbnb-setup

go 1.19

require (
	github.com/consensys/gnark v0.8.0
	github.com/consensys/gnark-crypto v0.9.1
	github.com/urfave/cli/v2 v2.25.0
)

require (
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/rs/zerolog v1.29.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/consensys/gnark => ../gnark

replace github.com/consensys/gnark-crypto => ../gnark-crypto

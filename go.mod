module github.com/bnbchain/zkbnb-setup

go 1.19

require (
	github.com/consensys/gnark v0.8.0
	github.com/consensys/gnark-crypto v0.9.1
	github.com/stretchr/testify v1.8.1
	github.com/urfave/cli/v2 v2.25.0
)

require (
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/google/pprof v0.0.0-20230207041349-798e818bf904 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/rs/zerolog v1.29.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

// replace github.com/consensys/gnark => github.com/bnb-chain/gnark v0.7.2-0.20230412065523-4d344ff30ab3
replace github.com/consensys/gnark => ../gnark

// replace github.com/consensys/gnark-crypto => github.com/bnb-chain/gnark-crypto v0.8.1-0.20230412133626-30223a679fb7
replace github.com/consensys/gnark-crypto => ../gnark-crypto

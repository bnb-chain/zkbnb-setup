# Guide to MPC Contribution Ceremony 
This tool allows users to run MPC ceremony for generating the proving and verifying keys for Groth16 protocol as presented in [BGM17](https://eprint.iacr.org/2017/1050.pdf). We removed the beacon contribution since it was proved in [KMSV21](https://eprint.iacr.org/2021/219.pdf) that the security of the generated SRS still holds without it.

# Pre-requisites
1. Install git https://github.com/git-guides/install-git
2. Install Go https://go.dev/doc/install
3. Minimum RAM requirements is 16GB

# Phase One 
This phase is to generate universal structured reference string (SRS) based on a power `p`.
The value of `2ᵖ` determines the maximum number of constraints for circuits setup in the second phase.

## Participants
1. Coordinator is responsible for initializing, coordinating and verifying contributions.
2. Contributors are chosen sequentially by the coordinator to contribute randomness to SRS. More importantly, contributors are requested to attest their contributions to the ceremony (e.g. social media announcement).

## Initialization
**Note** Value between `<>` are arguments replaced by actual values during the setup
1. Coordinator run the command `zkbnb-setup p1n <p> <output.ph1>`.

## Contribution
This is a sequential process that will be repeated for each contributor.
1. The coordinator sends the latest `*.ph1` file to the current contributor
2. The contributor run the command `zkbnb-setup p1c <input.ph1> <output.ph1>`.
3. Upon successful contribution, the program will output **contribution hash** which must be attested to
4. The contributor sends the output file back to the coordinator
5. The coordinator verifies the file by running `zkbnb-setup p1v <output.ph1>`. 
6. Upon successful verification, the coordinator asks the contributor to attest their contribution.


**Security Note** It is important for the coordinator to keep track of the contribution hashes output by `zkbnb-setup p1v` to determine whether the user has maliciously replaced previous contributions or re-initiated one on its own

# Phase 2
This phase is circuit-specific, so if you have `n` circuits, then you need to run this phase `n` times.

### Initialization
Depending on the R1CS file, the coordinator run one of the following commands:
1. Regular R1CS: `zkbnb-setup p2n <lastPhase1Contribution.ph1> <r1cs> <initialPhase2Contribution.ph2>`.
2. Parted R1CS: `zkbnb-setup p2np <phase1Path> <r1csPath> <outputPhase2> <#constraints> <#nbR1C> <batchSize>`

## Contribution
This process is similar to phase 1, except we use commands `p2c` and `p2v`
This is a sequential process that will be repeated for each contributor.
1. The coordinator sends the latest `*.ph2` file to the current contributor
2. The contributor run the command `zkbnb-setup p2c <input.ph2> <output.ph2>`.
3. Upon successful contribution, the program will output **contribution hash** which must be attested to
4. The contributor sends the output file back to the coordinator
5. The coordinator verifies the file by running `zkbnb-setup p2v <output.ph2> <initialPhase2Contribution.ph2>`.
6. Upon successful verification, the coordinator asks the contributor to attest their contribution.

**Security Note** It is important for the coordinator to keep track of the contribution hashes output by `zkbnb-setup p2v` to determine whether the user has maliciously replaced previous contributions or re-initiated one on its own

# Keys Extraction
At the end of the ceremony, the coordinator runs `zkbnb-setup keys <lastPhase2Contribution.ph2>` which will output **Groth16 bn254 curve** `pk` and `vk` files
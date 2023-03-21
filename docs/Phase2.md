# Phase 2
This phase is circuit-specific, so if you have `n` circuits, then you need to run this phase `n` times. The final output will include the hash of circuit's R1CS file. 

### Initialization
1. The coordinator runs the command `zkbnb-setup p2n <inputPhase1Path> <inputR1CS> <outputPhase2> <evals>`.

## Contributions 
This process is similar to phase 1, except we use commands `p2c` and `p2v`
This is a sequential process that will be repeated for each contributor.
1. The coordinator sends the latest `*.ph2` file to the current contributor
2. The contributor run the command `zkbnb-setup p2c <inputPath.ph2> <outputPath.ph2>`.
3. Upon successful contribution, the program will output **contribution hash** which must be attested to
4. The contributor sends the output file back to the coordinator
5. The coordinator verifies the file by running `zkbnb-setup p2v <inputPath.ph1>`. For example, `zkbnb-setup p2v 006.ph2`
6. Upon successful verification, the coordinator asks the contributor to attest their contribution.

**Security Note** It is important for the coordinator to keep track of the contribution hashes output by `zkbnb-setup p2v` to determine whether the user has maliciously replaced previous contributions or re-initiated one on its own

## Keys Extraction
After the last contribution to phase 2 has been verified and attested successfully, the coordinator runs `zkbnb-setup keys <inputPath.ph2> <evalsPath>` which will output **Groth16 bn254 curve** `provingKey` and `verifyingKey` files that can be read by **gnark**
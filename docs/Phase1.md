# Phase One 

This phase is to generate universal structured reference string (SRS) based on a power `p`.
The value of `2ᵖ` determines the maximum number of constraints for circuits setup in the second phase.

## Participants
1. Coordinator is responsible for initializing, coordinating and verifying contributions.
2. Contributors are chosen sequentially by the coordinator to contribute randomness to SRS. More importantly, contributors are requested to attest their contributions to the ceremony (e.g. social media announcement).
## Pre-requisites
1. Minimum RAM requirements is 8GB

## Initialization
**Note** Value between `<>` are arguments replaced by actual values during the setup
1. Coordinator run the command `zkbnb-setup p1n <p> <output.ph1>`.

## Contributions
This is a sequential process that will be repeated for each contributor.
1. The coordinator sends the latest `*.ph1` file to the current contributor
2. The contributor run the command `zkbnb-setup p1c <input.ph1> <output.ph1>`.
3. Upon successful contribution, the program will output **contribution hash** which must be attested to
4. The contributor sends the output file back to the coordinator
5. The coordinator verifies the file by running `zkbnb-setup p1v <output.ph1>`. 
6. Upon successful verification, the coordinator asks the contributor to attest their contribution.


## Security Note
**It is important for the coordinator to keep track of the contribution hashes output by `zkbnb-setup p1v` to determine whether the user has maliciously replaced previous contributions or re-initiated one on its own**
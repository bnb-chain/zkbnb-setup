# Phase 1 File Format for *.ph1
    Header                      <3 bytes>
    {
        Power                   <1 byte>
        #Contributions          <2 bytes>
    }
    Parameters                  <192<2ᵖ>+32 bytes>
    {                           
        {[τ]₁}                  <32(2²ᵖ-1) bytes>
        {[ατ]₁}                 <32(2ᴾ) bytes>
        {[βτ]₁}                 <32(2ᴾ) bytes>
        {[τ]₂}                  <64(2ᴾ) bytes>
        [β]₂                    <64 bytes>
    }
    Contributions               <640(#Contributions) bytes>
    {
        {                       <640 bytes>
            [τ]₁                <32 bytes>
            [α]₁                <32 bytes>
            [β]₁                <32 bytes>
            [τ]₂                <64 bytes>
            [β]₂                <64 bytes>
            {sτ₁, sxτ₁, spxτ₂}  <128 bytes>
            {sα₁, sxα₁, spxα₂}  <128 bytes>
            {sβ₁, sxβ₁, spxβ₂}  <128 bytes>
            hash                <32 bytes>
        }
        ...
    }



# Phase 2 File Format for *.ph2
    Header                      <18 bytes>
    {
        #Witness                <4  bytes>
        #Public                 <4  bytes>
        #Constraints            <4  bytes>
        #Domain                 <4  bytes>
        #Contributions          <2  bytes>
    }
    Parameters {
        [δ]₁                    <32 bytes>
        [δ]₂                    <64 bytes>
        Z                       <32(#Domain-1) bytes>
        L                       <32(#Public + #Witness) bytes>
    }
    Contributions
    {
        {
            [δ]₁                <32 bytes>
            [s]₁                <32 bytes>
            [sx]₁               <32 bytes>
            [spx]₂              <64 bytes>
            hash                <32 bytes>
        }
        ...
    }


**Note** only the Witness part of L is updated in contributions

The following files are generated as part of `zkbnb-setup p2n` command and will be used at the end of phase 2 by `zkbnb-setup keys` command.
The main objective is to reduce the storage/bandwidth cost for phase 2 contributors since these files aren't used during `zkbnb-setup p2c`
# Phase 2 Lagrange File Format
    LagrangeSRS
    {
        Domain                  <4 bytes>
        {[τ]₁}                  <32(2ᵖ)+4 bytes>
        {[ατ]₁}                 <32(2ᴾ)+4 bytes>
        {[βτ]₁}                 <32(2ᴾ)+4 bytes>
        {[τ]₂}                  <64(2ᴾ)+4 bytes>
    }

# Phase 2 Evaluation File Format for *.ev

    Evaluation 
    {
        [α]₁                    <32 bytes>
        [β]₁                    <32 bytes>
        [β]₂                    <64 bytes>
        [A]₁                    <32(#Witness+#Public)+4 bytes>
        [B]₁                    <32(#Witness+#Public)+4 bytes>
        [B]₂                    <64(#Witness+#Public)+4 bytes>
    }
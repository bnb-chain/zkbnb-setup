# Phase 1 File Format
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
    LagrangeSRS
    {
        {[τ]₁}                  <32(2ᵖ)+4 bytes>
        {[ατ]₁}                 <32(2ᴾ)+4 bytes>
        {[βτ]₁}                 <32(2ᴾ)+4 bytes>
        {[τ]₂}                  <64(2ᴾ)+4 bytes>
    }



# Phase 2 File Format
    Header 
    {
        #Internal               <4  bytes>
        #Public                 <4  bytes>
        #Constraints            <4  bytes>
        #Domain                 <4  bytes>
        #Contributions          <2 bytes>
        [α]₁                    <32 bytes>
        [β]₁                    <32 bytes>
        [β]₂                    <64 bytes>
    }
    Evaluation {
        [A]₁                    <32(#Internal+#Public)+4 bytes>
        [B]₁                    <32(#Internal+#Public)+4 bytes>
        [B]₂                    <64(#Internal+#Public)+4 bytes>
    }
    Parameters {
        [δ]₁                    <32 bytes>
        [δ]₂                    <32 bytes>
        L                       <32(#Public + #Internal) bytes>
        H                       <32(#Domain-1) bytes>
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


**Note** only the internal part of L is updated in contributions
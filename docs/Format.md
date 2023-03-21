# Phase 1 File Format
    Header 
    {
        Power                   <1 byte>
        #Contributions          <2 bytes>
    }
    Parameters
    {
        {[τ]₁}                  <32(2²ᵖ⁻¹) bytes>
        {[ατ]₁}                 <32(2ᴾ) bytes>
        {[βτ]₁}                 <32(2ᴾ) bytes>
        {[τ]₂}                  <64(2ᴾ) bytes>
        [β]₂                    <64 bytes>
    }
    Contributions
    {
        {
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
        {[τ]₁}                  <32(2ᵖ) bytes>
        {[ατ]₁}                 <32(2ᴾ) bytes>
        {[βτ]₁}                 <32(2ᴾ) bytes>
        {[τ]₂}                  <64(2ᴾ) bytes>
    }



# Phase 2 File Format
    Header 
    {
        R1CSHash                <32 bytes>
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
        [A]₁                    <32(#Internal+#Public) bytes>
        [B]₁                    <32(#Internal+#Public) bytes>
        [VK]₁                   <32(#Public) bytes>
        [B]₂                    <64(#Internal+#Public) bytes>
    }
    Parameters {
        [δ]₁                    <32 bytes>
        [δ]₂                    <32 bytes>
        L                       <32(#Internal) bytes>
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

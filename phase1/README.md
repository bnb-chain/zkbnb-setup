# File Structure for Contributions
    Header 
    {
        Power               <1 byte>
        #Contributions      <2 bytes>
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
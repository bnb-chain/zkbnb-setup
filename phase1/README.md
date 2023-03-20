# File Structure

    Power <1 byte>
    #Contributions <2 bytes>
    {g₁, [τ]₁, [τ²]₁, …, [τ²ⁿ⁻²]₁}
    {[α]₁, α[τ]₁, α[τ²]₁, …, α[τⁿ⁻¹]₁}
    {[β]₁, β[τ]₁, β[τ²]₁, …, β[τⁿ⁻¹]₁}
    {g₂, [τ]₂, [τ²]₂, …, [τⁿ⁻¹]₂}
    {[β]₂}
    Contributions each is <640 bytes>
    {
        {
            {[τ]₁, [α]₁, [β]₁, [τ]₂, [β]₂} <224 bytes>
            {sτ₁, sxτ₁, spxτ₂} <128 bytes>
            {sα₁, sxα₁, spxα₂} <128 bytes>
            {sβ₁, sxβ₁, spxβ₂} <128 bytes>
            hash <32 bytes>
        },
        ...
    }
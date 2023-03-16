    power <byte> {N= 2^power}
    nContributions <byte>
    <384N+66 bytes>
    {[τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ⁿ⁻²]₁}
    {α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τⁿ⁻¹]₁}
    {β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τⁿ⁻¹]₁}
    {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τⁿ⁻¹]₂}
    {[β]₂}
    Contributions each is 640 bytes
    {
        {
            {[τ¹]₁, α[τ¹]₁, β[τ¹]₁, [τ¹]₂, [β]₂} <224 bytes>
            {sτ₁, sxτ₁, spxτ₂} <128 bytes>
            {sα₁, sxα₁, spxα₂} <128 bytes>
            {sβ₁, sxβ₁, spxβ₂} <128 bytes>
            hash <32 bytes>
        },
        ...
    }
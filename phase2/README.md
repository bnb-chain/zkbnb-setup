# File Structure
    Header 
    {
        R1CSHash        <32 bytes>
        #Internal       <4  bytes>
        #Public         <4  bytes>
        #Constraints    <4  bytes>
        #Domain         <4  bytes>
        #Contributions  <2 bytes>
        [α]₁            <32 bytes>
        [β]₁            <32 bytes>
        [β]₂            <64 bytes>
    }
    Evaluation {
        [A]₁            <32(#Internal+#Public) bytes>
        [B]₁            <32(#Internal+#Public) bytes>
        [VK]₁           <32(#Public) bytes>
        [B]₂            <64(#Internal+#Public) bytes>
    }
    Parameters {
        [δ]₁             <32 bytes>
        [δ]₂             <32 bytes>
        L                <32(#Internal) bytes>
        H                <32(#Domain-1) bytes>
    }
    Contributions
    {
        [δ]₁            <32 bytes>
        [s]₁            <32 bytes>
        [sx]₁           <32 bytes>
        [spx]₂          <64 bytes>
        hash            <32 bytes>
    }
    ...
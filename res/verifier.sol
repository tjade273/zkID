pragma solidity ^0.4.14;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point p) pure internal returns (G1Point) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return the sum of two points of G1
    function addition(G1Point p1, G1Point p2) internal returns (G1Point r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 6, 0, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }
    /// @return the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point p, uint s) internal returns (G1Point r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 7, 0, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] p1, G2Point[] p2) internal returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 8, 0, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point a1, G2Point a2, G1Point b1, G2Point b2) internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point a1, G2Point a2,
            G1Point b1, G2Point b2,
            G1Point c1, G2Point c2
    ) internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point a1, G2Point a2,
            G1Point b1, G2Point b2,
            G1Point c1, G2Point c2,
            G1Point d1, G2Point d2
    ) internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
library Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G2Point A;
        Pairing.G1Point B;
        Pairing.G2Point C;
        Pairing.G2Point gamma;
        Pairing.G1Point gammaBeta1;
        Pairing.G2Point gammaBeta2;
        Pairing.G2Point Z;
        Pairing.G1Point[] IC;
    }
    struct ProofData{
        Proof proof;
        uint[5] inputs;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G1Point A_p;
        Pairing.G2Point B;
        Pairing.G1Point B_p;
        Pairing.G1Point C;
        Pairing.G1Point C_p;
        Pairing.G1Point K;
        Pairing.G1Point H;
    }
    function verifyingKey() pure internal returns (VerifyingKey vk) {
        vk.A = Pairing.G2Point([0x18fe7482652209241622f8bc214c3622cf1c1e23bd3449bc2d2b1d7b0e44b581, 0x701c3c59f61e1555c1dd22c317bd41d188ac34cc7bef707491a324f2b0505d2], [0x1079040967631cad92f2aa67d56c32c3d8703b11d6ec7abbde3239aac81a7c06, 0x1dae2acf1fff1298bca9b9f380f9c736b6e73e1afcc6e098982cbeeebc0f20f7]);
        vk.B = Pairing.G1Point(0xdd66f3d4cf16d117142601b6015c4bd4116a5bf1e0885d633cec37a375d51fc, 0x71932030983ad4e7d92799bbb9d80293997532ed2620cdea03206b61e98ae42);
        vk.C = Pairing.G2Point([0x1cc5d2714dee48148375d3dbbfa2ec7af183f88186b48790ed576592e1e7a742, 0x1cdc1ca4d1bbbcb602d9090cfbe84b7339dfe12926c48d6ebb2361656449824f], [0xd5bec11cd00fb575efab5fc2e70d3cbdc06c8ef2d17389aaed096d61ba465e8, 0x164d0ee285846cf3545cce27c698fe7cb6742efaae6fdcadd92d91507cdd5905]);
        vk.gamma = Pairing.G2Point([0x55863186a00126bcaac0492324a2b12e8807a6ebb4da32d52ca2a238f1aed2e, 0x18718693398cb0a19f143f2dcfb130b467cff41ded8caf0e007e93689664af11], [0xe0b158bec70d0173ed8c3f88d072da3094a36d885762a0c899b68fdd6376bd0, 0x2b0ad76ec84e77d77f197499beb1ccd48fe077f80e7116ffe2da42851350d340]);
        vk.gammaBeta1 = Pairing.G1Point(0x2472a63de3e133ada35f3cdc6472224dde0130039ea6cdcf7b2d2dced562e0a9, 0x975a86d07b24b5f17c7fe8ae33762cb247576ea2227099191fcc2abb41d4343);
        vk.gammaBeta2 = Pairing.G2Point([0x10598d0424207ee3b1ade44bb55199ec68756beb56fd573d426a3056e6345e7f, 0x167e3eba8a01459f09851a6eeb5510a4f338b1dc1409cc993055328ea52846f9], [0x648b28ecbdb8ef1677d6795d03bde2ab81b597e051dc0340cdedca17fc7c657, 0x243f205849433d9862c85a8a00f0135b18b7122e054fdf10a6c4fea95d0bb606]);
        vk.Z = Pairing.G2Point([0x1c7dfaa92f296625c9e4431601cadf5eea38515ab1d05f1d9ca51c8342154c7c, 0x1be60aa44fa388da199aec53b31a703358c934cb1697f08dcac81b85287bc6fb], [0x2bba6d00cb1d6eb83b2f79d839ab32a92bb2e62d1b763c50930d35515df1ae72, 0x655cc74ab5faf7558684d3d4242d8a31458f49aa616618cc8a0db40b25e37b6]);
        vk.IC = new Pairing.G1Point[](6);
        vk.IC[0] = Pairing.G1Point(0x1a65b399892e1f50d2f5f8225d2779fee23d011dbef5f003a305b3e15147d89d, 0x2fa350baeb47f3e08c8b6355de3d9d07a213af47ed6f1d6d956afe024bf43990);
vk.IC[1] = Pairing.G1Point(0x138d4ea24bfbb8e127817a5b51bda6369e689dd400bb84e8ecee033f079e7499, 0xc8170ee59474296735cb761a89465a7e07340347ecea04c258d0d8426bfe162);
vk.IC[2] = Pairing.G1Point(0x12e92318e2613b0525ad2d1bc19a88e9628778cc5a349f88b6f650329416a570, 0x2c43a3c2b212180087ce8bf636506ce75b2935360881ed3b2f0da12bebf66cfb);
vk.IC[3] = Pairing.G1Point(0x2b6f1f271fc6544db5007b55352eb42c6a26ceac134a220ec9bdf1e0191865d7, 0x1d5de54ebd0f6c02c3d2ed02c847269edf04cb2afa83d313ef0bdb375fb17459);
vk.IC[4] = Pairing.G1Point(0x7e1f52b09b32ae40d0db3691df164a9a3657e80580b0c6d998a65f5af1c319d, 0x1d8badebb99cf760b7fa4630fb4985b2412481a3a482bf222f5f89e71a6d29c);
vk.IC[5] = Pairing.G1Point(0x175d8bf7814e64a1fa629d328e9bb607065f20b1f69a7aa536e2d3809e41cae6, 0x2374fae093e6a23dfd587ad56791724c75ed6e1d812cf2df3b6d6f8035d8738f);

    }
    function verify(uint[5] input, Proof proof) internal returns (uint) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd2(proof.A, vk.A, Pairing.negate(proof.A_p), Pairing.P2())) return 1;
        if (!Pairing.pairingProd2(vk.B, proof.B, Pairing.negate(proof.B_p), Pairing.P2())) return 2;
        if (!Pairing.pairingProd2(proof.C, vk.C, Pairing.negate(proof.C_p), Pairing.P2())) return 3;
        if (!Pairing.pairingProd3(
            proof.K, vk.gamma,
            Pairing.negate(Pairing.addition(vk_x, Pairing.addition(proof.A, proof.C))), vk.gammaBeta2,
            Pairing.negate(vk.gammaBeta1), proof.B
        )) return 4;
        if (!Pairing.pairingProd3(
                Pairing.addition(vk_x, proof.A), proof.B,
                Pairing.negate(proof.H), vk.Z,
                Pairing.negate(proof.C), Pairing.P2()
        )) return 5;
        return 0;
    }

    function parseProofData(Proof memory self, uint[18] data) internal {
      uint pos = 0;
      self.A = Pairing.G1Point(   data[pos++], data[pos++]);
      self.A_p = Pairing.G1Point( data[pos++], data[pos++]);
      self.B = Pairing.G2Point(  [data[pos++], data[pos++]], [data[pos++], data[pos++]]);
      self.B_p = Pairing.G1Point( data[pos++], data[pos++]);
      self.C = Pairing.G1Point(   data[pos++], data[pos++]);
      self.C_p = Pairing.G1Point( data[pos++], data[pos++]);
      self.H = Pairing.G1Point(   data[pos++], data[pos++]);
      self.K = Pairing.G1Point(   data[pos++], data[pos++]);
    }

    function parseProofsDataFromBytes(uint[] data, uint[] public_inputs, ProofData[] memory proofsData) internal{
        uint pos = 0;
        uint inputs_pos = 0;
        uint proofCount = 0;

        while(pos < data.length){
            ProofData memory proofData;

            /* Proof Parameters */
            proofData.proof.A = Pairing.G1Point(   data[pos++], data[pos++]);
            proofData.proof.A_p = Pairing.G1Point( data[pos++], data[pos++]);
            proofData.proof.B = Pairing.G2Point(  [data[pos++], data[pos++]], [data[pos++], data[pos++]]);
            proofData.proof.B_p = Pairing.G1Point( data[pos++], data[pos++]);
            proofData.proof.C = Pairing.G1Point(   data[pos++], data[pos++]);
            proofData.proof.C_p = Pairing.G1Point( data[pos++], data[pos++]);
            proofData.proof.H = Pairing.G1Point(   data[pos++], data[pos++]);
            proofData.proof.K = Pairing.G1Point(   data[pos++], data[pos++]);

            /* Public Inputs */
            uint input_len = data[inputs_pos++];

            for(uint i =0; i < input_len; i++){
                proofData.inputs[i] = public_inputs[inputs_pos++];
            }

            /* Add to proofsData */
            proofsData[proofCount] = proofData;
            ++proofCount;
        }
    }

    event Verified(string);
    function verifyTx(uint[] proofs_bytes, uint proof_count, uint[] public_inputs) public returns (bool r) {
        ProofData[] memory proofsData = new ProofData[](proof_count);
        parseProofsDataFromBytes(proofs_bytes,public_inputs,proofsData);
        for(uint i = 0; i < proofsData.length; i++){

            if (verify(proofsData[i].inputs, proofsData[i].proof) != 0) {
                return false;
            }
        }
        return true;
    }
}

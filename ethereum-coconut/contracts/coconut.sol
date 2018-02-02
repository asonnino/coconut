import "solidity-BN256G2/BN256G2.sol";

contract BN256PairingPrecompile {
    // From: https://medium.com/@rmercer/precompiles-solidity-e5d29bd428c4
    //
    // bn256Pairing takes arbitrarily many pairs of elliptic curve points, and
    // performs the pairing check e(g1, g2) = e(h1, h2), with g1 and h1 from G1,
    // and g2 and h2 from G2.
    //
    // - points from G1 have the form (x, y), as we have seen above;
    // - points from G2 have the form (a + ib, c + id), and a, b, c, d need be
    // supplied in the precompile call.
    //
    // The bn256Pairing code first checks that a multiple of 6 elements have
    // been sent, and then performs the pairings check(s).
    //
    function BN256Pairing(
        bytes32 x1, bytes32 y1,
        bytes32 a1, bytes32 b1, bytes32 c1, bytes32 d1,
        bytes32 x2, bytes32 y2,
        bytes32 a2, bytes32 b2, bytes32 c2, bytes32 d2
    ) returns(bool result);
}

library Coconut {
    struct CoconutInstance {
        int q; // number of messages
        int t; // threshold
        int n; // number of authorities
        uint256[] g2; // tuple of 4 integers representing one curve point on G2
        uint256[] g2_x; // tuple of 4 integers representing one curve point on G2
        uint256[] g2_y; // dynamic array consisting of a curve point (4 integers each) on G2 for each q
        uint256[] sigs; // dynamic array consisting of three curve points (2 integers each) on G1 for each n
    }

    //event TokenRequested(CoconutInstance storage instance,);

    function Create(int q, int t, int n, uint256[] g2, uint256[] g2_x, uint256[] g2_y) returns (CoconutInstance instance) {
        instance.q = q;
        instance.t = t;
        instance.n = n;
        instance.g2 = g2;
        instance.g2_x = g2_x;
        instance.g2_y = g2_y;

        // Optional: get a signature from the authorities and check that it verifies.
    }

    // clear_m - plaintext message
    // cm - tuple of 2 integers representing one curve point on G1
    // c - dynamic array consisting of two curve points (2 integers each) on G1 for each message
    function RequestToken(CoconutInstance storage self, string clear_m, uint256[] cm, uint256[] c) {
    }

    function IssueToken(CoconutInstance storage self, uint256[] sigs, int index) {
        // append sigs to self.sigs
    }

    // clear_m - plaintext message
    // g2 - tuple of 4 integers representing one curve point on G2
    // sig - tuple of 2x2 integers representing two curve point on G1
    function VerifyToken(CoconutInstance storage self, bytes32 clear_m, uint256[] sig) returns (bool) {
        uint256[4] aggr;
        (aggr[0], aggr[1], aggr[2], aggr[3]) = BN256G2.ECTwistMul(
            uint256(clear_m),
            self.g2_y[0], self.g2_y[1], self.g2_y[2], self.g2_y[3]
        );

        BN256PairingPrecompile(0x0000000000000000000000000000000000000001).BN256Pairing(
            bytes32(sig[0]), bytes32(sig[1]),
            bytes32(aggr[0]), bytes32(aggr[1]), bytes32(aggr[2]), bytes32(aggr[3]),
            bytes32(sig[2]), bytes32(sig[3]),
            bytes32(self.g2[0]), bytes32(self.g2[1]), bytes32(self.g2[2]), bytes32(self.g2[3])
        );
    }
}

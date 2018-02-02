contract Precompile {
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
    function bn256Pairing(bytes32 x, bytes32 y, bytes32 a, bytes32 b, bytes32 c, bytes32 d) returns(result);
}

library Coconut {
    struct CoconutInstance {
        int q; // number of messages
        int t; // threshold
        int n; // number of authorities
        int[] g2; // tuple of 4 integers representing one curve point on G2
        int[] g2_x; // tuple of 4 integers representing one curve point on G2
        int[] g2_y; // dynamic array consisting of a curve point (4 integers each) on G2 for each q
        int[] sigs; // dynamic array consisting of three curve points (2 integers each) on G1 for each n
    }

    //event TokenRequested(CoconutInstance storage instance,);

    function Create(int q, int t, int n, int[] g2, int[] g2_x, int[] g2_y) returns (CoconutInstance instance) {
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
    function RequestToken(CoconutInstance storage self, string clear_m, int[] cm, int[] c) {
    }

    function IssueToken(CoconutInstance storage self, int[] sigs, int index) {
        // append sigs to self.sigs
    }

    // clear_m - plaintext message
    // g2 - tuple of 4 integers representing one curve point on G2
    // sig - tuple of 2 integers representing one curve point on G1
    function VerifyToken(CoconutInstance storage self, string clear_m, int[] sig) {
    }
}

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

contract Cocotumbler {
    function TumblerSetup() {
    }

    function TumblerDeposit() {
    }

    function TumblerWithdraw() {
    }

    function TumblerTeardown() {
    }
}

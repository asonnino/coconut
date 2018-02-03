import "solidity-BN256G2/BN256G2.sol";

pragma solidity ^0.4.19;

/**
 * @title Coconut threshold issuance credentials library
 */
library Coconut {
    struct CoconutInstance {
        int q; // number of messages
        int t; // threshold
        int n; // number of authorities
        uint256[4] g2; // array of 4 integers representing a point on G2
        uint256[4] g2_x; // array of 4 integers representing a point on G2
        uint256[] g2_y; // dynamic array consisting of a point on G2 (4 integers) for each q
    }

    /**
     * @notice Initialise an instance of Coconut with the parameters of authorities
     * @param q the number of messages per token that will be signed
     * @param t the threshold of authorities that must sign a token
     * @param g2 a twist point
     * @param g2_x a twist point
     * @param g2_y a twist point for each q
     * @return a CoconutInstance
     */
    function Create(int q, int t, int n, uint256[4] g2, uint256[4] g2_x, uint256[] g2_y) public pure returns (CoconutInstance instance) {
        assert(q == 1); // only one clear message is supported at the moment

        instance.q = q;
        instance.t = t;
        instance.n = n;
        instance.g2 = g2;
        instance.g2_x = g2_x;
        instance.g2_y = g2_y;
    }

    /**
     * @notice Verify that a token is valid
     * @param self the CoconutInstance
     * @param clear_m the clear message
     * @param sig two curve points
     * @return true if the token verifies, otherwise false
     */
    function VerifyToken(CoconutInstance storage self, bytes32 clear_m, uint256[4] sig) public view returns (bool result) {
        uint256[4] memory aggr;
        (aggr[0], aggr[1], aggr[2], aggr[3]) = BN256G2.ECTwistMul(
            uint256(clear_m),
            self.g2_y[0], self.g2_y[1], self.g2_y[2], self.g2_y[3]
        );

        uint256[12] memory indata;
        (indata[0], indata[1]) = (sig[0], sig[1]);
        (indata[2], indata[3], indata[4], indata[5]) = (aggr[0], aggr[1], aggr[2], aggr[3]);
        (indata[6], indata[7]) = (sig[2], sig[3]);
        (indata[8], indata[9], indata[10], indata[11]) = (self.g2[0], self.g2[1], self.g2[2], self.g2[3]);

        assembly {
            staticcall(sub(gas, 2000), 0x8, indata, 384, result, 1)
            pop
        }
    }
}

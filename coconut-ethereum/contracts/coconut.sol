import "solidity-BN256G2/BN256G2.sol";

pragma solidity ^0.4.19;
pragma experimental ABIEncoderV2;

/**
 * @title Coconut threshold issuance credentials library
 * @author Mustafa Al-Bassam (mus@musalbas.com)
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
     * @notice Verify that a token is valid
     * @param self the CoconutInstance
     * @param clear_m the clear message
     * @param sig two curve points
     * @return true if the token verifies, otherwise false
     */
    function VerifyToken(CoconutInstance self, uint256 clear_m, uint256[4] sig) public view returns (bool result) {
        uint256[4] memory aggr;
        (aggr[0], aggr[1], aggr[2], aggr[3]) = BN256G2.ECTwistMul(
            clear_m,
            self.g2_y[0], self.g2_y[1], self.g2_y[2], self.g2_y[3]
        );
        (aggr[0], aggr[1], aggr[2], aggr[3]) = BN256G2.ECTwistAdd(
            self.g2_x[0], self.g2_x[1], self.g2_x[2], self.g2_x[3],
            aggr[0], aggr[1], aggr[2], aggr[3]
        );

        uint256[12] memory indata;
        (indata[0], indata[1]) = (sig[0], sig[1]);
        (indata[2], indata[3], indata[4], indata[5]) = (aggr[1], aggr[0], aggr[3], aggr[2]);
        (indata[6], indata[7]) = (sig[2], BN256G2.GetFieldModulus() - sig[3]);
        (indata[8], indata[9], indata[10], indata[11]) = (self.g2[1], self.g2[0], self.g2[3], self.g2[2]);

        uint256[1] memory outdata;
        assembly {
            staticcall(sub(gas, 2000), 8, indata, 384, outdata, 32)
            pop
        }

        return outdata[0] != 0;
    }
}

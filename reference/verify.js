const { ethers } = require("ethers");

const domain = {
    name: "SecurityCouncil",
    version: "1",
    chainId: 1,
    verifyingContract: "0x66e4431266dc7e04e7d8b7fe9d2181253df7f410"
};

const types = {
    ApproveUpgradeSecurityCouncil: [
        { name: "id", type: "bytes32" }
    ]
};

const message = {
    id: "0x5ebd899d036aae29b12babe196b11380d8304e98ac86390ac18a56ff51ada9bd"
};

function computeMessageHash() {
    const hash = ethers.TypedDataEncoder.hash(domain, types, message);

    console.log("Message Hash:", hash);
    return hash;
}

// Compute and display the hash
computeMessageHash();

// Expected Result
// 0x76ea36b85e6de361baa7cb21a064a2a985bd2ce751407345d408cee923e94a41
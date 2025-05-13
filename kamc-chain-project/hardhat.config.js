require("@nomicfoundation/hardhat-toolbox");

/** @type import(\'hardhat/config\').HardhatUserConfig */
module.exports = {
  solidity: "0.8.20",
  networks: {
    hardhat: {
      chainId: 31339, // Thay đổi chainId
      port: 8547
    },
    localhost_kamc: {
      url: "http://127.0.0.1:8547",
      chainId: 31339,
    }
  }
};

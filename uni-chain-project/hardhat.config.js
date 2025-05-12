require("@nomicfoundation/hardhat-toolbox");

/** @type import(\'hardhat/config\').HardhatUserConfig */
module.exports = {
  solidity: "0.8.20", // Hoặc phiên bản bạn dùng
  networks: {
    hardhat: { // Mạng mặc định khi chạy npx hardhat node
      chainId: 1337, // Mặc định
      port: 8545, // Hardhat tự động chọn nếu không chỉ định khi chạy node
    },
    localhost_uni: {
      url: "http://127.0.0.1:8545",
      chainId: 31337, // Có thể tùy chỉnh chainId cho từng mạng
      // accounts: [privateKey1, privateKey2, ...] // Nếu cần tài khoản cụ thể
    }
  }
};

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UniversityRegistry {
    address public owner;
    mapping(address => bool) public registeredUniversities;
    mapping(bytes32 => CredentialInfo) public credentials;

    struct CredentialInfo {
        address universityAddress;
        string studentId_on_KAMC_Chain;
        string credentialType;
        string major;
        uint256 graduationYear;
        string offChainEncryptedDataPointer;
        bytes32 degreeHash; // Hash of core credential info + offChainEncryptedDataPointer
        bool isValid;
    }

    event UniversityRegistered(address indexed universityAddress);
    event CredentialIssued(
        address indexed universityAddress,
        string studentId_on_KAMC_Chain,
        bytes32 indexed degreeHash,
        string offChainEncryptedDataPointer
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function.");
        _;
    }

    modifier onlyRegisteredUniversity() {
        require(registeredUniversities[msg.sender], "Only registered universities can call this function.");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerUniversity(address _universityAddress) external onlyOwner {
        require(!registeredUniversities[_universityAddress], "University already registered.");
        registeredUniversities[_universityAddress] = true;
        emit UniversityRegistered(_universityAddress);
    }

    function issueCredential(
        string calldata _studentId_on_KAMC_Chain,
        string calldata _credentialType,
        string calldata _major,
        uint256 _graduationYear,
        string calldata _offChainEncryptedDataPointer,
        bytes32 _degreeHash
    ) external onlyRegisteredUniversity {
        require(credentials[_degreeHash].isValid == false, "Degree hash already exists.");

        credentials[_degreeHash] = CredentialInfo(
            msg.sender,
            _studentId_on_KAMC_Chain,
            _credentialType,
            _major,
            _graduationYear,
            _offChainEncryptedDataPointer,
            _degreeHash,
            true
        );

        emit CredentialIssued(
            msg.sender,
            _studentId_on_KAMC_Chain,
            _degreeHash,
            _offChainEncryptedDataPointer
        );
    }

    function getCredentialInfo(bytes32 _degreeHash) external view returns (CredentialInfo memory) {
        require(credentials[_degreeHash].isValid, "Credential not found.");
        return credentials[_degreeHash];
    }
}

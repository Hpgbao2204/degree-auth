// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StudentConsentRegistry {
    address public owner;

    struct ConsentInfo {
        string studentId_on_KAMC_Chain;
        bytes32 degreeHash_on_UNI_Chain;
        string employerId_on_KAMC_Chain;
        uint256 expiryTimestamp;
        bool isActive;
    }

    // Mapping: studentId_KAMC -> degreeHash_UNI -> employerId_KAMC -> ConsentInfo
    mapping(string => mapping(bytes32 => mapping(string => ConsentInfo))) public consents;

    event ConsentGranted(
        string indexed studentId_on_KAMC_Chain,
        bytes32 indexed degreeHash_on_UNI_Chain,
        string indexed employerId_on_KAMC_Chain,
        uint256 expiryTimestamp
    );

    event ConsentRevoked(
        string indexed studentId_on_KAMC_Chain,
        bytes32 indexed degreeHash_on_UNI_Chain,
        string indexed employerId_on_KAMC_Chain
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function.");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function grantConsent(
        string calldata _studentId_on_KAMC_Chain, // Student identity (e.g., their address on KAMC chain or a unique ID)
        bytes32 _degreeHash_on_UNI_Chain,
        string calldata _employerId_on_KAMC_Chain,
        uint256 _consentDurationInSeconds
    ) external { // Assuming student (or their DApp) calls this
        require(_consentDurationInSeconds > 0, "Consent duration must be positive.");
        uint256 expiry = block.timestamp + _consentDurationInSeconds;

        // Optional: Check if student is authorized to grant consent for this degreeHash
        // This might involve a call to another contract or an off-chain check by the relayer/DApp

        consents[_studentId_on_KAMC_Chain][_degreeHash_on_UNI_Chain][_employerId_on_KAMC_Chain] = ConsentInfo(
            _studentId_on_KAMC_Chain,
            _degreeHash_on_UNI_Chain,
            _employerId_on_KAMC_Chain,
            expiry,
            true
        );

        emit ConsentGranted(_studentId_on_KAMC_Chain, _degreeHash_on_UNI_Chain, _employerId_on_KAMC_Chain, expiry);
    }

    function revokeConsent(
        string calldata _studentId_on_KAMC_Chain,
        bytes32 _degreeHash_on_UNI_Chain,
        string calldata _employerId_on_KAMC_Chain
    ) external { // Assuming student (or their DApp) calls this
        ConsentInfo storage consent = consents[_studentId_on_KAMC_Chain][_degreeHash_on_UNI_Chain][_employerId_on_KAMC_Chain];
        require(consent.isActive, "Consent not active or does not exist.");
        // Optional: Verify msg.sender is authorized to revoke this consent (e.g., is the student)

        consent.isActive = false;
        emit ConsentRevoked(_studentId_on_KAMC_Chain, _degreeHash_on_UNI_Chain, _employerId_on_KAMC_Chain);
    }

    function checkConsent(
        string calldata _studentId_on_KAMC_Chain,
        bytes32 _degreeHash_on_UNI_Chain,
        string calldata _employerId_on_KAMC_Chain
    ) external view returns (bool isActive, uint256 expiryTimestamp) {
        ConsentInfo storage consent = consents[_studentId_on_KAMC_Chain][_degreeHash_on_UNI_Chain][_employerId_on_KAMC_Chain];
        if (consent.isActive && block.timestamp < consent.expiryTimestamp) {
            return (true, consent.expiryTimestamp);
        }
        return (false, 0);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VerificationRequester {
    address public owner;
    address public relayerAddress; // Address authorized to submit verification results

    struct VerificationRequest {
        uint256 requestId;
        address employerAddress_on_EMP_Chain; // Address of employer on this EMP-Chain
        string employerId_on_KAMC_Chain;
        string studentId_on_KAMC_Chain;
        bytes32 degreeHash_on_UNI_Chain;
        string purpose;
        bool isOpen;
        bool resultSubmitted;
        bool verificationStatus; // true for verified, false for not verified/rejected
        string verifierComment;
    }

    uint256 public nextRequestId;
    mapping(uint256 => VerificationRequest) public requests;

    event VerificationRequested(
        uint256 indexed requestId,
        address indexed employerAddress,
        string employerId_on_KAMC_Chain,
        string studentId_on_KAMC_Chain,
        bytes32 indexed degreeHash
    );

    event VerificationCompleted(
        uint256 indexed requestId,
        string studentId_on_KAMC_Chain,
        bytes32 indexed degreeHash,
        bool verificationStatus,
        string comment
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function.");
        _;
    }
    
    modifier onlyRelayer() {
        require(msg.sender == relayerAddress, "Only authorized relayer can call this function.");
        _;
    }

    constructor() {
        owner = msg.sender;
        relayerAddress = msg.sender; // Initially, owner is also the relayer
        nextRequestId = 1;
    }

    function setRelayerAddress(address _relayerAddress) external onlyOwner {
        relayerAddress = _relayerAddress;
    }

    function requestVerification(
        string calldata _employerId_on_KAMC_Chain,
        string calldata _studentId_on_KAMC_Chain,
        bytes32 _degreeHash_on_UNI_Chain,
        string calldata _purpose
    ) external returns (uint256) {
        uint256 currentRequestId = nextRequestId;
        requests[currentRequestId] = VerificationRequest(
            currentRequestId,
            msg.sender, // employerAddress on this chain
            _employerId_on_KAMC_Chain,
            _studentId_on_KAMC_Chain,
            _degreeHash_on_UNI_Chain,
            _purpose,
            true, // isOpen
            false, // resultSubmitted
            false, // verificationStatus (default)
            ""
        );
        nextRequestId++;
        emit VerificationRequested(currentRequestId, msg.sender, _employerId_on_KAMC_Chain, _studentId_on_KAMC_Chain, _degreeHash_on_UNI_Chain);
        return currentRequestId;
    }

    function submitVerificationResult(
        uint256 _requestId,
        bool _status,
        string calldata _comment
    ) external onlyRelayer {
        VerificationRequest storage requestToUpdate = requests[_requestId];
        require(requestToUpdate.requestId != 0, "Request not found.");
        require(requestToUpdate.isOpen, "Request already closed.");
        require(!requestToUpdate.resultSubmitted, "Result already submitted for this request.");

        requestToUpdate.verificationStatus = _status;
        requestToUpdate.verifierComment = _comment;
        requestToUpdate.resultSubmitted = true;
        requestToUpdate.isOpen = false; // Close the request

        emit VerificationCompleted(_requestId, requestToUpdate.studentId_on_KAMC_Chain, requestToUpdate.degreeHash_on_UNI_Chain, _status, _comment);
    }

    function getRequestInfo(uint256 _requestId) external view returns (VerificationRequest memory) {
        require(requests[_requestId].requestId != 0, "Request not found.");
        return requests[_requestId];
    }
}

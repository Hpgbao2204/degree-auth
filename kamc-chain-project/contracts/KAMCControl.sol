// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract KAMCControl {
    address public owner;
    mapping(address => bool) public kamcMembers;
    uint256 public kamcMemberCount;
    // In a real scenario, more sophisticated KAMC member management would be needed.

    string public tssPublicKey; // Stored as a string, could be bytes for actual key data
    string public abePublicParams; // Stored as a string

    struct ABEKeyGenerationRequest {
        uint256 requestId;
        string requesterId_on_KAMC_Chain; // Entity ID from EntityRegistry
        string attributes_json; // JSON string of requested attributes
        // string tssApprovalPayload; // Off-chain proof that KAMC members approved via TSS
        bool isProcessed;
        string encryptedKeyMaterialPointer; // Pointer to where the encrypted ABE key is stored off-chain
    }

    uint256 public nextABEKeyRequestId;
    mapping(uint256 => ABEKeyGenerationRequest) public abeKeyRequests;

    event KAMCManagerChanged(address indexed newManager);
    event KAMCMemberAdded(address indexed memberAddress);
    event KAMCMemberRemoved(address indexed memberAddress);
    event TSSPublicKeyUpdated(string newTSSPublicKey);
    event ABEPublicParamsUpdated(string newABEPublicParams);
    event ABEKeyGenerationRequested(
        uint256 indexed requestId,
        string indexed requesterId_on_KAMC_Chain,
        string attributes_json
    );
    event ABEKeyReady(
        uint256 indexed requestId,
        string indexed requesterId_on_KAMC_Chain,
        string encryptedKeyMaterialPointer
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function.");
        _;
    }

    modifier onlyKAMCMember() {
        require(
            kamcMembers[msg.sender],
            "Only KAMC members can call this function."
        );
        _;
    }

    // Modifier for relayer or authorized address to confirm ABE key generation
    address public relayerAddress;
    modifier onlyRelayer() {
        require(
            msg.sender == relayerAddress,
            "Only authorized relayer can call this function."
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        relayerAddress = msg.sender; // Owner is initially the relayer
        addKAMCMember(msg.sender); // Owner is the first KAMC member
        nextABEKeyRequestId = 1;
    }

    function setRelayerAddress(address _newRelayerAddress) external onlyOwner {
        relayerAddress = _newRelayerAddress;
    }

    function addKAMCMember(address _memberAddress) public onlyOwner {
        // Or by KAMC consensus
        require(
            !kamcMembers[_memberAddress],
            "Address is already a KAMC member."
        );
        kamcMembers[_memberAddress] = true;
        kamcMemberCount++;
        emit KAMCMemberAdded(_memberAddress);
    }

    function removeKAMCMember(address _memberAddress) external onlyOwner {
        // Or by KAMC consensus
        require(kamcMembers[_memberAddress], "Address is not a KAMC member.");
        kamcMembers[_memberAddress] = false;
        kamcMemberCount--;
        emit KAMCMemberRemoved(_memberAddress);
    }

    function updateTSSPublicKey(
        string calldata _newTSSPublicKey
    ) external onlyOwner {
        // Or by KAMC consensus
        tssPublicKey = _newTSSPublicKey;
        emit TSSPublicKeyUpdated(_newTSSPublicKey);
    }

    function updateABEPublicParams(
        string calldata _newABEPublicParams
    ) external onlyOwner {
        // Or by KAMC consensus
        abePublicParams = _newABEPublicParams;
        emit ABEPublicParamsUpdated(_newABEPublicParams);
    }

    function requestABEKeyGeneration(
        string calldata _requesterId_on_KAMC_Chain, // Entity ID from EntityRegistry
        string calldata _attributes_json
    )
        external
        returns (
            // string calldata _tssApprovalPayload // This would be verified off-chain by relayer before calling confirm
            uint256 requestId
        )
    {
        // Called by UNI for student, or EMP after consent
        // In a real system, there might be a fee or other checks here.
        // The _tssApprovalPayload is assumed to be handled off-chain by the relayer
        // before the relayer calls confirmABEKeyGenerated.
        // This contract focuses on logging the request and the final confirmation.

        requestId = nextABEKeyRequestId;
        abeKeyRequests[requestId] = ABEKeyGenerationRequest(
            requestId,
            _requesterId_on_KAMC_Chain,
            _attributes_json,
            // _tssApprovalPayload,
            false, // isProcessed
            "" // encryptedKeyMaterialPointer (initially empty)
        );
        nextABEKeyRequestId++;

        emit ABEKeyGenerationRequested(
            requestId,
            _requesterId_on_KAMC_Chain,
            _attributes_json
        );
        return requestId;
    }

    function confirmABEKeyGenerated(
        uint256 _requestId,
        string calldata _encryptedKeyMaterialPointer
    ) external onlyRelayer {
        // Called by the relayer after off-chain MPC/TSS and key storage
        ABEKeyGenerationRequest storage requestToUpdate = abeKeyRequests[
            _requestId
        ];
        require(requestToUpdate.requestId != 0, "ABE key request not found.");
        require(
            !requestToUpdate.isProcessed,
            "ABE key request already processed."
        );

        requestToUpdate
            .encryptedKeyMaterialPointer = _encryptedKeyMaterialPointer;
        requestToUpdate.isProcessed = true;

        emit ABEKeyReady(
            _requestId,
            requestToUpdate.requesterId_on_KAMC_Chain,
            _encryptedKeyMaterialPointer
        );
    }

    function getABEKeyGenerationRequest(
        uint256 _requestId
    ) external view returns (ABEKeyGenerationRequest memory) {
        require(
            abeKeyRequests[_requestId].requestId != 0,
            "ABE key request not found."
        );
        return abeKeyRequests[_requestId];
    }
}

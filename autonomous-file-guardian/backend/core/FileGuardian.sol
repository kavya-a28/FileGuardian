// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title FileGuardian
 * @dev A smart contract to register file hashes, log activity, and manage access
 * using a combination of SHA256 hashes for integrity and IPFS CIDs for storage.
 */
contract FileGuardian {

    // --- Structs ---

    struct FileRecord {
        string fileHash;        // SHA256 hash of the *encrypted* file for integrity checks
        address owner;          // The blockchain address of the file's owner
        uint256 timestamp;      // The block timestamp when the file was registered
        bool exists;            // Flag to check if the file ID is valid
        string metadata;        // JSON string for file name, size, etc.
        string ipfsCid;         // The IPFS Content ID (hash) pointing to the encrypted file data
    }
    
    struct ActivityLog {
        uint256 fileId;         // Reference to the file
        string action;          // Action type (e.g., "file_registered", "access_denied")
        string severity;        // Severity level (e.g., "info", "critical")
        address actor;          // The address that performed the action
        string details;         // Additional log details
        uint256 timestamp;      // The block timestamp when the log was created
    }
    
    struct TrustedUser {
        address userAddress;    // Trusted user's address
        string publicKey;       // Their public key (for future use, e.g., sharing decryption keys)
        uint256 grantedAt;      // When access was granted
        bool isActive;          // Access status
    }
    
    // --- State Variables ---
    
    mapping(uint256 => FileRecord) public files;
    mapping(uint256 => ActivityLog[]) public fileLogs;
    mapping(uint256 => mapping(address => TrustedUser)) public trustedUsers;
    mapping(uint256 => address[]) public fileAccessList;
    
    uint256 public fileCount;
    uint256 public logCount;
    
    // --- Events ---
    
    event FileRegistered(
        uint256 indexed fileId, 
        string fileHash, 
        address indexed owner, 
        uint256 timestamp,
        string ipfsCid  // Event now includes the IPFS CID
    );
        
    event ActivityLogged(uint256 indexed logId, uint256 indexed fileId, string action, address indexed actor);
    event AccessGranted(uint256 indexed fileId, address indexed owner, address indexed trustedUser);
    event AccessRevoked(uint256 indexed fileId, address indexed owner, address indexed trustedUser);
    event FileIntegrityVerified(uint256 indexed fileId, bool isValid, uint256 timestamp);
    
    // --- Modifiers ---
    
    modifier onlyFileOwner(uint256 _fileId) {
        require(files[_fileId].owner == msg.sender, "Not file owner");
        _;
    }
    
    modifier fileExists(uint256 _fileId) {
        require(files[_fileId].exists, "File does not exist");
        _;
    }
    
    // --- Core Functions ---

    /**
     * @dev Registers a new file, storing its integrity hash and IPFS location.
     * @param _fileHash The SHA256 hash of the encrypted file.
     * @param _metadata A JSON string containing file metadata (name, size).
     * @param _ipfsCid The IPFS Content ID (hash) where the encrypted file is stored.
     */
    function registerFile(
        string memory _fileHash,
        string memory _metadata,
        string memory _ipfsCid
    ) public returns (uint256) {
        fileCount++;
        
        files[fileCount] = FileRecord({
            fileHash: _fileHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            exists: true,
            metadata: _metadata,
            ipfsCid: _ipfsCid
        });
        
        emit FileRegistered(
            fileCount, 
            _fileHash, 
            msg.sender, 
            block.timestamp, 
            _ipfsCid
        );
        
        // Also log this as a standard activity
        _logActivity(fileCount, "file_registered", "info", "File registered on blockchain with IPFS");
        
        return fileCount;
    }
    
    /**
     * @dev Logs a new activity for a specific file.
     * @param _fileId The ID of the file to log against.
     * @param _action The name of the action (e.g., "encrypt", "decrypt").
     * @param _severity The severity of the log (e.g., "info", "warning", "critical").
     * @param _details A description of the activity.
     */
    function logActivity(
        uint256 _fileId,
        string memory _action,
        string memory _severity,
        string memory _details
    ) public fileExists(_fileId) {
        // Only the file owner or a trusted user can log activity
        require(hasAccess(_fileId, msg.sender), "Not authorized to log activity");
        _logActivity(_fileId, _action, _severity, _details);
    }
    
    /**
     * @dev Internal function to create and store a log.
     */
    function _logActivity(
        uint256 _fileId,
        string memory _action,
        string memory _severity,
        string memory _details
    ) internal {
        logCount++;
        
        ActivityLog memory newLog = ActivityLog({
            fileId: _fileId,
            action: _action,
            severity: _severity,
            actor: msg.sender,
            details: _details,
            timestamp: block.timestamp
        });
        
        fileLogs[_fileId].push(newLog);
        
        emit ActivityLogged(logCount, _fileId, _action, msg.sender);
    }
    
    /**
     * @dev Verifies the integrity of a file by comparing its current hash
     * to the hash stored on the blockchain.
     * @param _fileId The ID of the file to verify.
     * @param _currentHash The SHA256 hash of the file as it exists now.
     * @return bool True if the hashes match, false otherwise.
     */
    function verifyFileIntegrity(
        uint256 _fileId,
        string memory _currentHash
    ) public fileExists(_fileId) returns (bool) {
        bool isValid = keccak256(abi.encodePacked(files[_fileId].fileHash)) == 
                       keccak256(abi.encodePacked(_currentHash));
        
        emit FileIntegrityVerified(_fileId, isValid, block.timestamp);
        
        if (isValid) {
            _logActivity(_fileId, "integrity_verified", "info", "File integrity verified - hash matches");
        } else {
            _logActivity(_fileId, "integrity_violation", "critical", 
                "FILE TAMPERED - Hash mismatch detected!");
        }
        
        return isValid;
    }

    // --- Access Control Functions ---
    
    /**
     * @dev Grants access to a trusted user for a specific file.
     * @param _fileId The ID of the file.
     * @param _trustedUser The blockchain address of the user to grant access to.
     * @param _publicKey The public key of the trusted user.
     */
    function grantAccess(
        uint256 _fileId,
        address _trustedUser,
        string memory _publicKey
    ) public onlyFileOwner(_fileId) fileExists(_fileId) {
        require(_trustedUser != address(0), "Invalid address");
        require(_trustedUser != msg.sender, "Cannot grant access to self");
        
        trustedUsers[_fileId][_trustedUser] = TrustedUser({
            userAddress: _trustedUser,
            publicKey: _publicKey,
            grantedAt: block.timestamp,
            isActive: true
        });
        
        // Add to access list if not already there
        bool exists = false;
        for (uint i = 0; i < fileAccessList[_fileId].length; i++) {
            if (fileAccessList[_fileId][i] == _trustedUser) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            fileAccessList[_fileId].push(_trustedUser);
        }
        
        emit AccessGranted(_fileId, msg.sender, _trustedUser);
        
        _logActivity(_fileId, "access_granted", "info", 
            string(abi.encodePacked("Access granted to ", addressToString(_trustedUser))));
    }
    
    /**
     * @dev Revokes access from a trusted user.
     * @param _fileId The ID of the file.
     * @param _trustedUser The address to revoke access from.
     */
    function revokeAccess(
        uint256 _fileId,
        address _trustedUser
    ) public onlyFileOwner(_fileId) fileExists(_fileId) {
        require(trustedUsers[_fileId][_trustedUser].isActive, "User does not have access");
        
        trustedUsers[_fileId][_trustedUser].isActive = false;
        
        emit AccessRevoked(_fileId, msg.sender, _trustedUser);
        
        _logActivity(_fileId, "access_revoked", "warning",
            string(abi.encodePacked("Access revoked from ", addressToString(_trustedUser))));
    }

    // --- View (Read-Only) Functions ---

    /**
     * @dev Checks if a user has access to a file (either as owner or trusted user).
     */
    function hasAccess(uint256 _fileId, address _user) public view fileExists(_fileId) returns (bool) {
        if (files[_fileId].owner == _user) {
            return true;
        }
        return trustedUsers[_fileId][_user].isActive;
    }
    
    /**
     * @dev Gets all details for a specific file.
     */
    function getFile(uint256 _fileId) public view fileExists(_fileId) returns (
        string memory fileHash,
        address owner,
        uint256 timestamp,
        string memory metadata,
        string memory ipfsCid
    ) {
        FileRecord memory file = files[_fileId];
        return (
            file.fileHash, 
            file.owner, 
            file.timestamp, 
            file.metadata, 
            file.ipfsCid
        );
    }
    
    /**
     * @dev Gets all activity logs for a specific file.
     */
    function getFileLogs(uint256 _fileId) public view fileExists(_fileId) returns (ActivityLog[] memory) {
        return fileLogs[_fileId];
    }
    
    /**
     * @dev Gets the list of trusted user addresses for a file.
     */
    function getTrustedUsers(uint256 _fileId) public view fileExists(_fileId) returns (address[] memory) {
        return fileAccessList[_fileId];
    }
    
    /**
     * @dev Gets the details for a specific trusted user of a file.
     */
    function getTrustedUserDetails(uint256 _fileId, address _user) public view fileExists(_fileId) returns (
        string memory publicKey,
        uint256 grantedAt,
        bool isActive
    ) {
        TrustedUser memory trusted = trustedUsers[_fileId][_user];
        return (trusted.publicKey, trusted.grantedAt, trusted.isActive);
    }
    
    // --- Utility Functions ---
    
    /**
     * @dev Converts a blockchain address to a string.
     */
    function addressToString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint256 i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3+i*2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }
}
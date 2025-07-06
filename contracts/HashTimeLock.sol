// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// Standard Hash Time Locked Contract (Final Version)
contract HashTimeLock {

    struct Lock { // Struct now has 8 members
        address payable sender;
        address payable receiver;
        uint256 amount;
        bytes32 hashLock; // Keccak256(preimage)
        uint256 timeLock; // Absolute expiration timestamp
        bool withdrawn;
        bool refunded;
        bytes32 preimage; // Store preimage once revealed
    }

    mapping(bytes32 => Lock) public locks;

    event NewLock(
        bytes32 indexed lockId,
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        bytes32 hashLock,
        uint256 timeLock
    );
    event Withdrawn(bytes32 indexed lockId, bytes32 preimage);
    event Refunded(bytes32 indexed lockId);

    // Constructor is now empty
    constructor() {}

    function newLock(
        address payable receiver,
        bytes32 hashLock,
        uint256 timeLock
    ) external payable returns (bytes32 lockId) {
        require(msg.value > 0, "HTLC: Amount must be > 0");
        require(timeLock > block.timestamp + 60, "HTLC: Timelock must be in the future");

        lockId = keccak256(abi.encodePacked(msg.sender, receiver, msg.value, hashLock, timeLock, block.timestamp, gasleft()));
        require(locks[lockId].sender == address(0), "HTLC: Lock already exists");

        // ***** 修改: 使用命名字段初始化，且只包含 8 个成员 *****
        locks[lockId] = Lock({
            sender: payable(msg.sender),
            receiver: receiver,
            amount: msg.value,
            hashLock: hashLock,
            timeLock: timeLock,
            withdrawn: false,
            refunded: false,
            preimage: bytes32(0)
            // 移除 deliveryTimestamp: 0
        });
        // ***** 修改结束 *****

        // 移除之前多余的 positional 初始化尝试

        emit NewLock(lockId, msg.sender, receiver, msg.value, hashLock, timeLock);
        return lockId;
    }

    function withdraw(bytes32 lockId, bytes32 preimage) external returns (bool success) {
        Lock storage lock = locks[lockId];
        require(lock.sender != address(0), "HTLC: Lock does not exist");
        require(!lock.withdrawn, "HTLC: Already withdrawn");
        require(!lock.refunded, "HTLC: Already refunded");
        require(keccak256(abi.encodePacked(preimage)) == lock.hashLock, "HTLC: Invalid preimage");
        require(block.timestamp <= lock.timeLock, "HTLC: Timelock expired");
        // V_t 检查已移除

        lock.withdrawn = true;
        lock.preimage = preimage;
        lock.receiver.transfer(lock.amount);
        emit Withdrawn(lockId, preimage);
        return true;
    }

    function refund(bytes32 lockId) external returns (bool success) {
        Lock storage lock = locks[lockId];
        require(lock.sender != address(0), "HTLC: Lock does not exist");
        require(!lock.withdrawn, "HTLC: Already withdrawn");
        require(!lock.refunded, "HTLC: Already refunded");
        require(block.timestamp > lock.timeLock, "HTLC: Timelock not expired yet");

        lock.refunded = true;
        lock.sender.transfer(lock.amount);
        emit Refunded(lockId);
        return true;
    }

    // --- View Functions ---
    function getLockStatus(bytes32 lockId) public view returns (
        address sender, address receiver, uint256 amount, bytes32 hashLock,
        uint256 timeLock, bool withdrawn, bool refunded, bytes32 preimage
        ) {
        Lock storage lock = locks[lockId];
        // 返回 8 个字段
        return (lock.sender, lock.receiver, lock.amount, lock.hashLock,
                lock.timeLock, lock.withdrawn, lock.refunded, lock.preimage);
    }
}

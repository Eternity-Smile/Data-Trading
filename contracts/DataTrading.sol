// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract DataTrading {
    // 交易状态枚举
    enum TxStatus { Init, Active, L1_Verified, L2_Verified, Completed, Cancelled }

    // 每层数据的链上记录
    struct LayerData {
        bytes32 commitment; // 承诺占位符 (例如 txId) 或 ZKP 承诺哈希 C_i
        bytes32 dataHash;   // 数据层的 SHA256 哈希 L_i
        bool delivered;     // Seller 在成功 HTLC 提款并通过 V_t 检查后设置为 true
        bool verified;      // Buyer 在链下验证成功且 delivered=true 后设置为 true
        uint256 deliveryTimestamp; // Seller 调用 signalDelivery 时记录的时间戳 (用于 V_t)
    }

    // 交易主体结构
    struct Transaction {
        string dataId;          // 数据标识
        address payable seller; // 卖方地址
        address payable buyer;  // 买方地址
        TxStatus status;        // 当前交易状态
        uint256 t1; uint256 t2; uint256 t3; // HTLC 截止时间戳
        bytes32 h1; bytes32 h2; bytes32 h3; // HTLC 哈希锁 (Keccak256(O_i))
        LayerData[3] layers;    // 存储 3 层数据的数组
    }

    // 存储所有交易，以交易 ID (bytes32) 索引
    mapping(bytes32 => Transaction) public transactions;
    // 买方验证的固定时间间隔 V_t (秒)
    uint256 public verificationInterval;

    // --- 事件 ---
    event TransactionCreated(bytes32 indexed txId, string dataId, address indexed seller, address indexed buyer);
    event TransactionParamsSet(bytes32 indexed txId, uint256 t1, uint256 t2, uint256 t3);
    event LayerInfoRegistered(bytes32 indexed txId, uint8 layerIndex, bytes32 dataHash);
    event DeliverySignaled(bytes32 indexed txId, uint8 indexed layerIndex, uint256 timestamp); // Seller 发出交付信号事件
    event LayerDeliveryConfirmed(bytes32 indexed txId, uint8 indexed layerIndex); // Seller 确认交付事件 (通过 V_t 检查后)
    event LayerVerificationConfirmed(bytes32 indexed txId, uint8 indexed layerIndex); // Buyer 确认验证事件
    event TransactionCompleted(bytes32 indexed txId);
    event TransactionCancelled(bytes32 indexed txId, string reason);

    // --- 修饰符 ---
    modifier onlySeller(bytes32 txId) { require(msg.sender == transactions[txId].seller, "DT: Only seller"); _; }
    modifier onlyBuyer(bytes32 txId) { require(msg.sender == transactions[txId].buyer, "DT: Only buyer"); _; }
    modifier transactionExists(bytes32 txId) { require(transactions[txId].seller != address(0), "DT: Tx missing"); _; }

    // --- 构造函数 ---
    constructor(uint256 _verificationInterval) {
        require(_verificationInterval > 0, "DT: V_t must be positive");
        verificationInterval = _verificationInterval; // 设置 V_t
    }

    // --- 核心功能函数 ---

    /**
     * @dev Seller 调用以创建新交易
     * @param _dataId 数据的唯一标识符
     * @param _buyer 买方地址
     * @return txId 生成的交易 ID (bytes32)
     */
    function createTransaction(string memory _dataId, address _buyer) external returns (bytes32 txId) {
        // On-chain: 计算交易 ID
        txId = keccak256(abi.encodePacked(_dataId, msg.sender, _buyer, block.timestamp));
        require(transactions[txId].seller == address(0), "DT: Tx ID collision");

        // On-chain: 初始化交易状态 (分步初始化避免编译器错误)
        Transaction storage newTx = transactions[txId];
        newTx.dataId = _dataId;
        newTx.seller = payable(msg.sender);
        newTx.buyer = payable(_buyer);
        newTx.status = TxStatus.Init;
        // 其他字段默认为 0 / false

        emit TransactionCreated(txId, _dataId, msg.sender, _buyer);
        return txId; // 返回交易 ID
    }

    /**
     * @dev Seller 调用以设置 HTLC 参数 (H1-3, T1-3)
     */
    function setTransactionParams(
        bytes32 txId,
        uint256 _t1, uint256 _t2, uint256 _t3,
        bytes32 _h1, bytes32 _h2, bytes32 _h3
    ) external onlySeller(txId) transactionExists(txId) {
        Transaction storage tx = transactions[txId];
        require(tx.status == TxStatus.Init, "DT: Can only set params in Init state");
        // On-chain: 验证时间戳有效性
        require(_t1 > block.timestamp && _t2 > _t1 && _t3 > _t2, "DT: Invalid timestamps");

        // On-chain: 存储 HTLC 参数并更新状态
        tx.t1 = _t1; tx.t2 = _t2; tx.t3 = _t3;
        tx.h1 = _h1; tx.h2 = _h2; tx.h3 = _h3;
        tx.status = TxStatus.Active;

        emit TransactionParamsSet(txId, _t1, _t2, _t3);
    }

    /**
     * @dev Seller 调用以注册每层数据的哈希 (SHA256)
     * @param commitmentPlaceholder 承诺占位符 (当前用 txId)
     * @param dataHash 数据层的 SHA256 哈希
     */
    function registerLayerInfo(bytes32 txId, uint8 layerIndex, bytes32 commitmentPlaceholder, bytes32 dataHash)
        external onlySeller(txId) transactionExists(txId)
    {
        require(layerIndex < 3, "DT: Invalid layer index");
        Transaction storage tx = transactions[txId];
        require(tx.status == TxStatus.Active, "DT: Transaction not active");
        require(tx.layers[layerIndex].dataHash == bytes32(0), "DT: Layer info already registered");

        // On-chain: 存储层信息
        tx.layers[layerIndex].commitment = commitmentPlaceholder;
        tx.layers[layerIndex].dataHash = dataHash;

        emit LayerInfoRegistered(txId, layerIndex, dataHash);
    }

    /**
     * @dev Seller 在链下发送数据包后调用，以记录交付信号时间戳 (用于 V_t)
     */
    function signalDelivery(bytes32 txId, uint8 layerIndex)
        external onlySeller(txId) transactionExists(txId)
    {
        require(layerIndex < 3, "DT: Invalid layer index");
        Transaction storage tx = transactions[txId];
        require(tx.status >= TxStatus.Active && tx.status < TxStatus.Completed, "DT: Invalid state for signaling");
        require(!tx.layers[layerIndex].delivered && tx.layers[layerIndex].deliveryTimestamp == 0, "DT: Delivery already signaled or confirmed");

        // On-chain: 记录交付信号时间戳
        tx.layers[layerIndex].deliveryTimestamp = block.timestamp;
        emit DeliverySignaled(txId, layerIndex, block.timestamp);
    }

    /**
     * @dev Seller 在成功从 HTLC 提款后调用，确认该层已交付 (需通过 V_t 检查)
     */
    function confirmDelivery(bytes32 txId, uint8 layerIndex)
        external onlySeller(txId) transactionExists(txId)
    {
        require(layerIndex < 3, "DT: Invalid layer index");
        Transaction storage tx = transactions[txId];
        require(tx.status >= TxStatus.Active && tx.status < TxStatus.Completed, "DT: Invalid state");
        require(tx.layers[layerIndex].deliveryTimestamp > 0, "DT: Delivery not signaled yet");
        // On-chain: 检查 V_t 时间间隔是否已过
        require(block.timestamp >= tx.layers[layerIndex].deliveryTimestamp + verificationInterval, "DT: Verification interval not passed");
        require(!tx.layers[layerIndex].delivered, "DT: Delivery already confirmed");

        // On-chain: 标记为已交付
        tx.layers[layerIndex].delivered = true;
        emit LayerDeliveryConfirmed(txId, layerIndex);
    }

    /**
     * @dev Buyer 在链下验证成功且 Seller 已确认交付后调用，确认该层已验证
     */
    function confirmVerification(bytes32 txId, uint8 layerIndex)
        external onlyBuyer(txId) transactionExists(txId)
    {
        require(layerIndex < 3, "DT: Invalid layer index");
        Transaction storage tx = transactions[txId];
        // On-chain: 检查 Seller 是否已确认交付
        require(tx.layers[layerIndex].delivered, "DT: Layer not yet delivered by seller");
        require(!tx.layers[layerIndex].verified, "DT: Verification already confirmed");

        // On-chain: 标记为已验证并更新交易状态
        tx.layers[layerIndex].verified = true;
        if (layerIndex == 0 && tx.status == TxStatus.Active) { tx.status = TxStatus.L1_Verified; }
        else if (layerIndex == 1 && tx.status == TxStatus.L1_Verified) { tx.status = TxStatus.L2_Verified; }
        else if (layerIndex == 2 && tx.status == TxStatus.L2_Verified) { tx.status = TxStatus.Completed; emit TransactionCompleted(txId); }

        emit LayerVerificationConfirmed(txId, layerIndex);
    }

    /**
     * @dev Seller 或 Buyer 调用以取消交易 (状态需 < Completed)
     */
    function cancelTransaction(bytes32 txId, string memory reason) external transactionExists(txId) {
        require(msg.sender == transactions[txId].seller || msg.sender == transactions[txId].buyer, "DT: Only participants");
        Transaction storage tx = transactions[txId];
        require(tx.status < TxStatus.Completed, "DT: Cannot cancel completed");
        require(tx.status != TxStatus.Cancelled, "DT: Already cancelled");
        // On-chain: 更新状态为 Cancelled
        tx.status = TxStatus.Cancelled;
        emit TransactionCancelled(txId, reason);
    }

    // --- View Functions ---
    function getTransactionStatus(bytes32 txId) public view transactionExists(txId) returns (TxStatus) { return transactions[txId].status; }
    function getTransactionHTLCParams(bytes32 txId) public view transactionExists(txId) returns (uint256, uint256, uint256, bytes32, bytes32, bytes32) { Transaction storage tx = transactions[txId]; return (tx.t1, tx.t2, tx.t3, tx.h1, tx.h2, tx.h3); }
    function getLayerDetails(bytes32 txId, uint8 layerIndex) public view transactionExists(txId) returns (bytes32 commitment, bytes32 dataHash, bool delivered, bool verified, uint256 deliveryTimestamp) { require(layerIndex < 3, "DT: Invalid layer index"); LayerData storage layer = transactions[txId].layers[layerIndex]; return (layer.commitment, layer.dataHash, layer.delivered, layer.verified, layer.deliveryTimestamp); }
}

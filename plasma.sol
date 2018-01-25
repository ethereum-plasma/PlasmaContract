pragma solidity ^0.4.19;
import './RLP.sol';
import './MinHeap.sol';

contract PlasmaChainManager {
    using RLP for bytes;
    using RLP for RLP.RLPItem;
    using RLP for RLP.Iterator;
    using MinHeapLib for MinHeapLib.Heap;

    bytes constant PersonalMessagePrefixBytes = "\x19Ethereum Signed Message:\n68";
    uint32 constant blockHeaderLength = 133;

    struct BlockHeader {
        uint32 blockNumber;
        bytes32 previousHash;
        bytes32 merkleRoot;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct DepositRecord {
        uint32 n;
        uint32 ctr;
    }

    enum WithdrawStatus {
        Created,
        Challenged,
        Complete
    }

    struct WithdrawRecord {
        uint256 blockNumber;
        uint256 txIndex;
        uint256 oIndex;
        address beneficiary;
        WithdrawStatus status;
        uint256 timeStarted;
        uint256 timeEnded;
    }

    address public owner;
    uint32 public lastBlockNumber;
    uint32 public depositCounter;
    mapping(address => bool) public operators;
    mapping(uint256 => BlockHeader) public headers;
    mapping(address => DepositRecord[]) public depositRecords;
    mapping(uint256 => WithdrawRecord) public withdrawRecords;
    MinHeapLib.Heap exits;

    function PlasmaChainManager() public {
        owner = msg.sender;
        lastBlockNumber = 0;
        depositCounter = 0;
    }

    function setOperator(address operator, bool status)
        public
        returns (bool success)
    {
        require(msg.sender == owner);
        operators[operator] = status;
        return true;
    }

    event HeaderSubmittedEvent(address signer, uint32 blockNumber);

    function submitBlockHeader(bytes header) public returns (bool success) {
        require(operators[msg.sender]);
        require(header.length == blockHeaderLength);

        bytes4 blockNumber;
        bytes32 previousHash;
        bytes32 merkleRoot;
        bytes32 sigR;
        bytes32 sigS;
        bytes1 sigV;
        assembly {
            let data := add(header, 0x20)
            blockNumber := mload(data)
            previousHash := mload(add(data, 4))
            merkleRoot := mload(add(data, 36))
            sigR := mload(add(data, 68))
            sigS := mload(add(data, 100))
            sigV := mload(add(data, 132))
            if lt(sigV, 27) { sigV := add(sigV, 27) }
        }

        // Check the block number.
        require(uint8(blockNumber) == lastBlockNumber + 1);

        // Check the signature.
        bytes32 blockHash = keccak256(PersonalMessagePrefixBytes, blockNumber,
            previousHash, merkleRoot);
        address signer = ecrecover(blockHash, uint8(sigV), sigR, sigS);
        require(msg.sender == signer);

        // Append the new header.
        BlockHeader memory newHeader = BlockHeader({
            blockNumber: uint8(blockNumber),
            previousHash: previousHash,
            merkleRoot: merkleRoot,
            r: sigR,
            s: sigS,
            v: uint8(sigV)
        });
        headers[uint8(blockNumber)] = newHeader;

        // Increment the block number by 1 and reset the deposit counter.
        lastBlockNumber += 1;
        depositCounter = 0;
        HeaderSubmittedEvent(signer, uint8(blockNumber));
        return true;
    }

    event DepositEvent(address from, uint256 amount, uint32 indexed n, uint32 ctr);

    function deposit() payable public returns (bool success) {
        DepositRecord memory newDeposit = DepositRecord({
            n: lastBlockNumber,
            ctr: depositCounter
        });
        depositRecords[msg.sender].push(newDeposit);
        depositCounter += 1;
        DepositEvent(msg.sender, msg.value, newDeposit.n, newDeposit.ctr);
        return true;
    }

    event WithdrawalStartedEvent(uint256 withdrawalId);

    function startWithdrawal(
        uint256 blockNumber,
        uint256 txIndex,
        uint256 oIndex,
        bytes targetTx,
        bytes proof
    )
        public
        returns (uint256 withdrawalId)
    {
        BlockHeader memory header = headers[blockNumber];
        require(header.blockNumber > 0);

        var txList = targetTx.toRLPItem().toList();
        require(txList.length == 13);

        // Check if the target transaction is in the block.
        require(isValidProof(header.merkleRoot, targetTx, proof));

        // Check if the transaction owner is the sender.
        address txOwner = txList[6 + 2 * oIndex].toAddress();
        require(txOwner == msg.sender);

        // Check if the withdrawal exists.
        withdrawalId = blockNumber * 1000000000 + txIndex * 10000 + oIndex;
        WithdrawRecord storage record = withdrawRecords[withdrawalId];
        require(record.blockNumber == 0);

        // Construct a new withdrawal and add its ID to the heap.
        record.blockNumber = blockNumber;
        record.txIndex = txIndex;
        record.oIndex = oIndex;
        record.beneficiary = txOwner;
        record.status = WithdrawStatus.Created;
        record.timeStarted = now;
        exits.add(withdrawalId);

        WithdrawalStartedEvent(withdrawalId);
        return withdrawalId;
    }

    event WithdrawalChallengedEvent(uint256 withdrawalId);

    function challengeWithdrawal(
        uint256 withdrawalId,
        uint256 blockNumber,
        uint256 txIndex,
        uint256 oIndex,
        bytes targetTx,
        bytes proof
    )
        public
        returns (bool success)
    {
        BlockHeader memory header = headers[blockNumber];
        require(header.blockNumber > 0);

        // Check if the transaction is in the block.
        require(isValidProof(header.merkleRoot, targetTx, proof));

        // Check if the withdrawal exists.
        WithdrawRecord storage record = withdrawRecords[withdrawalId];
        require(record.blockNumber > 0);

        bytes4 utxoBlockNumber;
        bytes1 utxoTxIndex;
        assembly {
            let data := add(targetTx, 0x20)
            utxoBlockNumber := mload(data)
            utxoTxIndex := mload(add(data, 4))
        }

        // The transaction spends the given withdrawal on plasma chain.
        if (record.blockNumber == uint32(utxoBlockNumber) &&
            record.txIndex == uint32(utxoTxIndex)) {
            record.timeEnded = now;
            record.status = WithdrawStatus.Challenged;
            WithdrawalChallengedEvent(withdrawalId);
            return true;
        }

        return false;
    }

    event WithdrawalCompleteEvent(uint256 withdrawalId, uint32 indexed n,
        uint256 blockNumber, uint256 txIndex);

    function finalizeWithdrawal() public returns (bool success) {
        uint256 withdrawalId = exits.peek();

        WithdrawRecord storage record = withdrawRecords[withdrawalId];

        // If the top most withdrawal is challenged, just pop it and do nothing.
        if (record.status == WithdrawStatus.Challenged) {
            exits.pop();
            return false;
        }

        require(record.blockNumber > 0);
        require(record.status == WithdrawStatus.Created);
        // require(now >= record.timeStarted + (7 days));
        require(now >= record.timeStarted + 1 minutes);

        exits.pop();
        record.timeEnded = now;
        record.status = WithdrawStatus.Complete;
        record.beneficiary.transfer(1 ether);
        WithdrawalCompleteEvent(withdrawalId, lastBlockNumber,
            record.blockNumber, record.txIndex);
        return true;
    }

    function isValidProof(bytes32 root, bytes target, bytes proof)
        pure
        internal
        returns (bool valid)
    {
        bytes32 hash = keccak256(target);
        for (uint i = 32; i < proof.length; i += 33) {
            bytes1 flag;
            bytes32 sibling;
            assembly {
                flag := mload(add(proof, i))
                sibling := mload(add(add(proof, i), 1))
            }
            if (flag == 0) {
                hash = keccak256(sibling, hash);
            } else if (flag == 1) {
                hash = keccak256(hash, sibling);
            }
        }
        return hash == root;
    }
}

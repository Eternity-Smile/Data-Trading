# backend/src/web3_utils.py
from web3 import Web3, exceptions
import json
import os
import time
import logging
from decimal import Decimal, getcontext

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)-7s] %(message)s')
getcontext().prec = 18

class Web3Utils:
    # ... (__init__, load_contracts, _get_nonce, _build_tx_options, sign_and_send_transaction 保持不变, 使用 #61 版本) ...
    def __init__(self, provider_url='http://localhost:8545'):
        self.w3 = Web3(Web3.HTTPProvider(provider_url, request_kwargs={'timeout': 120}))
        if not self.w3.is_connected(): raise ConnectionError(f"Cannot connect to Ethereum node at {provider_url}")
        logging.info(f"Connected to Ethereum node: {provider_url}")
        try: self.chain_id = self.w3.eth.chain_id; logging.info(f"Chain ID: {self.chain_id}")
        except Exception as e: logging.error(f"Failed to get chain ID: {e}"); raise ConnectionError("Failed to get network ID.") from e
        self.contracts_loaded = False; self.data_trading = None; self.hash_time_lock = None
        try:
            self.load_contracts()
            if self.data_trading and self.hash_time_lock: self.contracts_loaded = True; logging.info("All required contracts loaded successfully.")
            else: logging.error("One or more contracts failed to load properly.")
        except Exception as e: logging.error(f"Error loading contracts during initialization: {e}")

    def load_contracts(self):
        network_id = str(self.chain_id)
        logging.info(f"Attempting to load contracts for network ID: {network_id}")
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        build_dir = os.path.join(project_root, 'build', 'contracts')
        # Load DataTrading
        dt_artifact_path = os.path.join(build_dir, 'DataTrading.json')
        if not os.path.exists(dt_artifact_path): logging.error(f"DataTrading artifact not found: {dt_artifact_path}")
        else:
            try:
                with open(dt_artifact_path, 'r', encoding='utf-8') as f: dt_contract_json = json.load(f)
                self.data_trading_abi = dt_contract_json['abi']
                self.data_trading_address = self.w3.to_checksum_address(dt_contract_json['networks'][network_id]['address'])
                self.data_trading = self.w3.eth.contract(address=self.data_trading_address, abi=self.data_trading_abi)
                logging.info(f"DataTrading loaded at: {self.data_trading_address}")
            except KeyError: logging.error(f"DataTrading deployment not found on network ID {network_id}.")
            except Exception as e: logging.error(f"Failed to load DataTrading: {e}")
        # Load HashTimeLock
        htlc_artifact_path = os.path.join(build_dir, 'HashTimeLock.json')
        if not os.path.exists(htlc_artifact_path): logging.error(f"HashTimeLock artifact not found: {htlc_artifact_path}")
        else:
            try:
                with open(htlc_artifact_path, 'r', encoding='utf-8') as f: htlc_contract_json = json.load(f)
                self.hash_time_lock_abi = htlc_contract_json['abi']
                self.hash_time_lock_address = self.w3.to_checksum_address(htlc_contract_json['networks'][network_id]['address'])
                self.hash_time_lock = self.w3.eth.contract(address=self.hash_time_lock_address, abi=self.hash_time_lock_abi)
                logging.info(f"HashTimeLock loaded at: {self.hash_time_lock_address}")
            except KeyError: logging.error(f"HashTimeLock deployment not found on network ID {network_id}.")
            except Exception as e: logging.error(f"Failed to load HashTimeLock: {e}")

    def _get_nonce(self, address):
        return self.w3.eth.get_transaction_count(self.w3.to_checksum_address(address))

    def _build_tx_options(self, from_address, value_wei=0, gas=None, gas_price=None):
        checksum_address = self.w3.to_checksum_address(from_address)
        options = { 'from': checksum_address, 'nonce': self._get_nonce(checksum_address), 'value': value_wei, 'chainId': self.chain_id }
        if gas: options['gas'] = gas
        if gas_price: options['gasPrice'] = gas_price
        else:
             try: options['gasPrice'] = int(self.w3.eth.gas_price * Decimal("1.1"))
             except Exception as e: logging.warning(f"Gas price fetch failed: {e}, using 20 Gwei."); options['gasPrice'] = self.w3.to_wei('20', 'gwei')
        logging.debug(f"Base Tx Options: {options}")
        return options

    def sign_and_send_transaction(self, function_call, sender_address, private_key, value_wei=0, gas=None):
        if not private_key: raise ValueError("Private key required.")
        sender_checksum = self.w3.to_checksum_address(sender_address)
        tx_options = self._build_tx_options(sender_checksum, value_wei=value_wei, gas=gas)
        try:
            if 'gas' not in tx_options:
                try:
                    estimated_gas = function_call.estimate_gas(tx_options)
                    tx_options['gas'] = int(estimated_gas * Decimal("1.2")) # 20% buffer
                    logging.info(f"Estimated gas: {estimated_gas}, using gas limit: {tx_options['gas']}")
                except exceptions.ContractLogicError as e: logging.error(f"Gas estimation failed (potential revert): {e}"); tx_options['gas'] = 3_000_000; logging.warning(f"Using default gas limit: {tx_options['gas']}")
                except Exception as e: logging.warning(f"Could not estimate gas: {e}, using default 3,000,000."); tx_options['gas'] = 3_000_000

            transaction = function_call.build_transaction(tx_options)
            logging.debug(f"Built Transaction: {transaction}")
            signed_tx = self.w3.eth.account.sign_transaction(transaction, private_key)
            logging.debug(f"Signed Tx Hash: {signed_tx.hash.hex()}")
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction) # Corrected attribute
            logging.info(f"Transaction sent, Hash: {tx_hash.hex()}")
            logging.info("Waiting for transaction receipt...")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            logging.info(f"Tx confirmed in block: {receipt.blockNumber}, Gas used: {receipt.gasUsed}")
            logging.debug(f"Receipt details: {receipt}")
            if receipt.status == 0: logging.error(f"Transaction {tx_hash.hex()} REVERTED!"); raise Exception(f"Tx {tx_hash.hex()} failed (reverted).")
            return receipt
        except exceptions.TimeExhausted: logging.error(f"Timeout waiting for tx receipt {tx_hash.hex()}."); raise TimeoutError(f"Timeout for {tx_hash.hex()}")
        except ValueError as e: logging.error(f"ValueError during tx: {e}"); raise e
        except Exception as e: logging.error(f"Unexpected error during sign/send: {e}"); import traceback; traceback.print_exc(); raise e

    # --- DataTrading Contract Interactions ---
    def dt_create_transaction(self, seller_address, private_key, data_id, buyer_address):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        func_call = self.data_trading.functions.createTransaction(data_id, self.w3.to_checksum_address(buyer_address))
        receipt = self.sign_and_send_transaction(func_call, seller_address, private_key)
        tx_id_bytes32 = None
        try:
            logs = self.data_trading.events.TransactionCreated().process_receipt(receipt) # Removed errors=
            if logs: tx_id_bytes32 = logs[0]['args']['txId']; logging.info(f"TransactionCreated event found, txId: {tx_id_bytes32.hex()}")
            else: logging.warning("TransactionCreated event log not found.")
        except Exception as e: logging.error(f"Error processing TransactionCreated event: {e}")
        if tx_id_bytes32 is None: logging.error("Failed to retrieve txId from event.")
        return receipt, tx_id_bytes32

    def dt_set_transaction_params(self, seller_address, private_key, tx_id, t1, t2, t3, h1_bytes, h2_bytes, h3_bytes):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        func_call = self.data_trading.functions.setTransactionParams(tx_id_bytes, int(t1), int(t2), int(t3), h1_bytes, h2_bytes, h3_bytes)
        return self.sign_and_send_transaction(func_call, seller_address, private_key)

    def dt_register_layer_info(self, seller_address, private_key, tx_id, layer_index, commitment_placeholder_bytes, data_hash_hex):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        if not isinstance(commitment_placeholder_bytes, bytes): raise TypeError(f"commitment_placeholder must be bytes")
        c_bytes = commitment_placeholder_bytes.ljust(32, b'\0')[:32]
        if isinstance(data_hash_hex, str) and data_hash_hex.startswith('0x'): dh_bytes = bytes.fromhex(data_hash_hex[2:])
        elif isinstance(data_hash_hex, str): dh_bytes = bytes.fromhex(data_hash_hex)
        elif isinstance(data_hash_hex, bytes): dh_bytes = data_hash_hex
        else: raise TypeError(f"Invalid data_hash type: {type(data_hash_hex)}")
        dh_bytes = dh_bytes.ljust(32, b'\0')[:32]
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        logging.debug(f"Calling registerLayerInfo: txId={tx_id_bytes.hex()}, layer={layer_index}, c={c_bytes.hex()}, dh={dh_bytes.hex()}")
        func_call = self.data_trading.functions.registerLayerInfo(tx_id_bytes, layer_index, c_bytes, dh_bytes)
        return self.sign_and_send_transaction(func_call, seller_address, private_key)

    # ***** 新增: 调用 signalDelivery 函数 *****
    def dt_signal_delivery(self, seller_address, private_key, tx_id, layer_index):
        """Calls signalDelivery on DataTrading contract."""
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        logging.info(f"Seller signaling delivery for Tx {tx_id_bytes.hex()} Layer {layer_index}...")
        func_call = self.data_trading.functions.signalDelivery(tx_id_bytes, layer_index)
        return self.sign_and_send_transaction(func_call, seller_address, private_key)
    # ***** 新增结束 *****

    def dt_confirm_layer_delivery(self, seller_address, private_key, tx_id, layer_index):
        # ... (保持不变, 合约内部会检查 V_t) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        func_call = self.data_trading.functions.confirmDelivery(tx_id_bytes, layer_index)
        return self.sign_and_send_transaction(func_call, seller_address, private_key)

    # ***** 已修改: 重命名函数并修正其内部对合约函数的调用 *****
    def dt_confirm_verification(self, buyer_address, private_key, tx_id, layer_index):
        """
        调用 DataTrading 智能合约上的 'confirmVerification' 函数。
        (此函数原名为 dt_confirm_layer_verification, 已修正以匹配合约函数名)。
        """
        # 检查 DataTrading 合约实例是否已加载
        if not self.data_trading:
            logging.error("DataTrading 合约实例未加载。")
            raise RuntimeError("DataTrading 合约未加载。")

        # 确保 tx_id 是 bytes 类型 (32字节)
        if isinstance(tx_id, str):
            # 处理 '0x' 前缀（如果存在）
            if tx_id.startswith('0x'):
                tx_id_bytes = bytes.fromhex(tx_id[2:])
            else:
                tx_id_bytes = bytes.fromhex(tx_id)
        elif isinstance(tx_id, bytes):
            tx_id_bytes = tx_id
        else:
            # 如果类型不正确，则抛出错误
            raise TypeError(f"tx_id 类型无效: {type(tx_id)}")

        # 检查 tx_id 长度 (通常应为 32)
        if len(tx_id_bytes) != 32:
             logging.warning(f"tx_id 长度不是 32 字节: {len(tx_id_bytes)}。请确保它是正确的交易 ID。")
             # 根据需要，可以选择填充或报错
             # tx_id_bytes = tx_id_bytes.ljust(32, b'\0')[:32] # 填充示例

        # 确保 layer_index 是有效的整数 (0, 1, 或 2)
        if not isinstance(layer_index, int) or layer_index < 0 or layer_index >= 3:
             raise ValueError(f"无效的 layer_index: {layer_index}。必须是 0, 1, 或 2。")

        logging.info(f"准备调用 DataTrading.confirmVerification 对于 TxID {tx_id_bytes.hex()} 层 {layer_index}")
        try:
            # ***** 关键修正处: 使用正确的合约函数名 'confirmVerification' *****
            func_call = self.data_trading.functions.confirmVerification(
                tx_id_bytes,
                layer_index
            )
            # ***** 修正结束 *****

            # 使用已有的辅助函数签名并发送交易
            logging.debug(f"正在为 confirmVerification 调用 sign_and_send_transaction...")
            receipt = self.sign_and_send_transaction(func_call, buyer_address, private_key)
            logging.info(f"confirmVerification 交易成功。回执状态: {receipt.get('status', 'N/A')}")
            # 返回完整的交易回执
            return receipt

        except exceptions.ContractLogicError as e:
            # 对合约 revert 提供更具体的错误处理
            logging.error(f"调用 confirmVerification 时发生 ContractLogicError: {e}")
            logging.error(f"  参数: txId={tx_id_bytes.hex()}, layerIndex={layer_index}")
            logging.error(f"  可能原因: 卖家尚未在链上确认交付? 该层已被验证? 请检查合约状态。")
            # 重新抛出特定异常，方便上层捕获
            raise e
        except Exception as e:
            # 捕获其他意外错误
            logging.error(f"dt_confirm_verification 中发生意外错误: {e}")
            logging.error(f"  参数: txId={tx_id_bytes.hex()}, layerIndex={layer_index}")
            # 重新抛出异常
            raise e
    # ***** 修改结束 *****

    def dt_cancel_transaction(self, sender_address, private_key, tx_id, reason):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        func_call = self.data_trading.functions.cancelTransaction(tx_id_bytes, reason)
        return self.sign_and_send_transaction(func_call, sender_address, private_key)

    # --- DataTrading Contract Views ---
    def dt_get_transaction_status(self, tx_id):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        return self.data_trading.functions.getTransactionStatus(tx_id_bytes).call()

    def dt_get_transaction_htlc_params(self, tx_id):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        return self.data_trading.functions.getTransactionHTLCParams(tx_id_bytes).call()

    def dt_get_layer_details(self, tx_id, layer_index):
        # ... (保持不变) ...
        if not self.data_trading: raise RuntimeError("DataTrading contract not loaded.")
        tx_id_bytes = tx_id if isinstance(tx_id, bytes) else bytes.fromhex(tx_id[2:] if isinstance(tx_id, str) and tx_id.startswith('0x') else tx_id)
        return self.data_trading.functions.getLayerDetails(tx_id_bytes, layer_index).call()

    # --- HashTimeLock Contract Interactions ---
    def htlc_new_lock(self, sender_address, private_key, receiver_address, hash_lock_hex, time_lock_ts, amount_ether):
        # ... (保持不变) ...
        if not self.hash_time_lock: raise RuntimeError("HashTimeLock contract not loaded.")
        try: value_wei = self.w3.to_wei(Decimal(str(amount_ether)), 'ether')
        except Exception as e: logging.error(f"Invalid amount: {amount_ether}. {e}"); raise ValueError("Invalid amount") from e
        if isinstance(hash_lock_hex, str) and hash_lock_hex.startswith('0x'): hash_lock_bytes = bytes.fromhex(hash_lock_hex[2:])
        elif isinstance(hash_lock_hex, str): hash_lock_bytes = bytes.fromhex(hash_lock_hex)
        elif isinstance(hash_lock_hex, bytes): hash_lock_bytes = hash_lock_hex
        else: raise TypeError(f"Invalid hash_lock type: {type(hash_lock_hex)}")
        hash_lock_bytes = hash_lock_bytes.ljust(32, b'\0')[:32]
        func_call = self.hash_time_lock.functions.newLock( self.w3.to_checksum_address(receiver_address), hash_lock_bytes, int(time_lock_ts) )
        receipt = self.sign_and_send_transaction(func_call, sender_address, private_key, value_wei=value_wei)
        lock_id_bytes32 = None
        try:
            logs = self.hash_time_lock.events.NewLock().process_receipt(receipt) # Removed errors=
            if logs: lock_id_bytes32 = logs[0]['args']['lockId']; logging.info(f"NewLock event found, lockId: {lock_id_bytes32.hex()}")
            else: logging.warning("NewLock event log not found.")
        except Exception as e: logging.error(f"Error processing NewLock event: {e}")
        if lock_id_bytes32 is None: logging.error("Failed to retrieve lockId from NewLock event.")
        return receipt, lock_id_bytes32

    def htlc_withdraw(self, receiver_address, private_key, lock_id, preimage_bytes):
        # ... (保持不变, 合约内部会检查 V_t) ...
        if not self.hash_time_lock: raise RuntimeError("HashTimeLock contract not loaded.")
        if not isinstance(preimage_bytes, bytes) or len(preimage_bytes) != 32: raise TypeError("preimage must be 32 bytes")
        lock_id_bytes = lock_id if isinstance(lock_id, bytes) else bytes.fromhex(lock_id[2:] if isinstance(lock_id, str) and lock_id.startswith('0x') else lock_id)
        func_call = self.hash_time_lock.functions.withdraw(lock_id_bytes, preimage_bytes)
        receipt = self.sign_and_send_transaction(func_call, receiver_address, private_key)
        success = False
        try:
            logs = self.hash_time_lock.events.Withdrawn().process_receipt(receipt) # Removed errors=
            success = bool(logs)
            logging.info(f"HTLC Withdraw attempt {'succeeded (event found)' if success else 'failed (event not found)'}")
        except Exception as e: logging.error(f"Error processing Withdrawn event: {e}")
        return receipt, success

    def htlc_refund(self, sender_address, private_key, lock_id):
        # ... (保持不变) ...
        if not self.hash_time_lock: raise RuntimeError("HashTimeLock contract not loaded.")
        lock_id_bytes = lock_id if isinstance(lock_id, bytes) else bytes.fromhex(lock_id[2:] if isinstance(lock_id, str) and lock_id.startswith('0x') else lock_id)
        func_call = self.hash_time_lock.functions.refund(lock_id_bytes)
        receipt = self.sign_and_send_transaction(func_call, sender_address, private_key)
        success = False
        try:
            logs = self.hash_time_lock.events.Refunded().process_receipt(receipt) # Removed errors=
            success = bool(logs)
            logging.info(f"HTLC Refund attempt {'succeeded (event found)' if success else 'failed (event not found)'}")
        except Exception as e: logging.error(f"Error processing Refunded event: {e}")
        return receipt, success

    # --- HashTimeLock Contract Views ---
    def htlc_get_lock_status(self, lock_id):
        # ... (保持不变) ...
        if not self.hash_time_lock: raise RuntimeError("HashTimeLock contract not loaded.")
        lock_id_bytes = lock_id if isinstance(lock_id, bytes) else bytes.fromhex(lock_id[2:] if isinstance(lock_id, str) and lock_id.startswith('0x') else lock_id)
        return self.hash_time_lock.functions.getLockStatus(lock_id_bytes).call()

    # --- General Utility ---
    def get_accounts(self):
        # ... (保持不变) ...
        return self.w3.eth.accounts

    def get_balance(self, address):
        # ... (保持不变) ...
        checksum_address = self.w3.to_checksum_address(address)
        balance_wei = self.w3.eth.get_balance(checksum_address)
        return Decimal(balance_wei) / Decimal(10**18)


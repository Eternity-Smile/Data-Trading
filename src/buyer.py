# backend/src/buyer.py
import logging
from decimal import Decimal
import time
import uuid
import json
import os
import traceback
import subprocess
# 确保导入所有需要的模块和函数
try:
    from crypto_utils import CryptoUtils
    from web3_utils import Web3Utils
    from data_utils import DataUtils
    # 只从 snarkjs_utils 导入 ZKP 相关
    from snarkjs_utils import generate_witness_and_proof, verify_proof, hash_data_for_circuit
    # 从 crypto_utils 导入 Bn (如果 crypto_utils 定义了它 - 在 Petlib 可用时)
    # 但由于我们现在强制使用模拟，所以不需要导入 Bn
    # from crypto_utils import Bn
except ImportError as e: logging.error(f"Buyer Import Error: {e}"); raise

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)-7s] %(message)s')

class DataBuyer:
    def __init__(self, address, private_key):
        if not private_key: raise ValueError("Buyer requires private key.")
        self.address = address; self.private_key = private_key
        self.base_user_id = address
        self.user_id_details = None
        self.age = None
        self.credential_path = None
        self.identity_package = None # Store the prepared package
        self.data_dir = os.path.join('data', 'buyer')
        os.makedirs(self.data_dir, exist_ok=True)
        logging.info(f"Initializing Buyer: Addr={self.address}")

        self.crypto = CryptoUtils()
        self.web3 = Web3Utils()
        self.data_utils = DataUtils()

        self.rsa_private_key, self.rsa_public_key, self.vrf_private_key, self.vrf_public_key = self.crypto.generate_rsa_key_pair()
        self.rsa_public_key_str = self.rsa_public_key.decode('utf-8')
        self.vrf_public_key_pem = self.vrf_public_key # bytes

        self.transactions = {}
        self.received_data_store = {}
        try: self.balance = Decimal(self.web3.get_balance(self.address))
        except Exception as e: logging.warning(f"Buyer init balance fetch failed: {e}"); self.balance = Decimal("0.0")
        logging.info(f"Buyer Initial Balance: {self.balance:.8f} ETH")
        logging.info(f"Buyer RSA Public Key (for L3): {self.rsa_public_key_str[:50]}...")

    def update_balance(self):
        try: self.balance = Decimal(self.web3.get_balance(self.address)); logging.info(f"Buyer Balance Updated: {self.balance:.8f} ETH")
        except Exception as e: logging.warning(f"Could not update buyer balance: {e}")

    # --- 身份验证与凭证 ---
    def set_identity(self, age, id_str):
        """Sets and validates identity info format."""
        # (与 Seller 中 set_identity 的验证逻辑相同)
        logging.info(f"Buyer ({self.address[:8]}...): Setting identity Age={age}, ID={id_str}")
        if not isinstance(age, int) or not (18 < age < 150): logging.error("Invalid age."); return False
        if not isinstance(id_str, str) or len(id_str) != 18 or not id_str.isdigit(): logging.error("Invalid ID."); return False
        if not id_str.startswith("5001"): logging.error("Invalid ID prefix."); return False
        if id_str.endswith("00"): logging.error("Invalid ID suffix."); return False
        self.age = age; self.user_id_details = id_str
        logging.info("Buyer identity information set and format validated.")
        return True

# --- 最终正确版本的 prepare_identity_package 函数 ---
# --- 请在 seller.py 和 buyer.py 中同时【完整替换】此函数 ---

# --- MODIFIED prepare_identity_package function ---
# --- Please replace this function entirely in BOTH seller.py and buyer.py ---

    def prepare_identity_package(self):
        """
        Generates identity package. Includes:
        - Simulated Pedersen commitment (cm_pedersen) and related VRF proof.
        - Calculation of id_hash.
        - Generation of a Poseidon commitment cm = Poseidon(age, id_hash, r_poseidon).
        - Generation of ZKP pi_1 proving age > 18 and knowledge of (age, id_hash, r_poseidon)
          for the public Poseidon commitment cm.
        """
        if self.age is None or self.user_id_details is None:
            raise ValueError(f"{self.__class__.__name__} identity not set.")
        logging.info(f"{self.__class__.__name__} ({self.address[:8]}...): Preparing identity package...")

        age_str = str(self.age)
        id_str = self.user_id_details

        # --- Keep Pedersen Commitment and VRF Generation (as they might be used elsewhere) ---
        # 1a. Generate Simulated Pedersen Commitment (for potential use with Issuer/VRF)
        r_pedersen_hex = self.crypto.generate_random_r(64)
        cm_pedersen_str = None
        try:
            # Note: The inputs [age_str, id_str] here are for the *Pedersen* commit logic
            cm_pedersen_str = self.crypto.simulated_pedersen_commit([age_str, id_str], r_pedersen_hex)
            logging.info(f"  Simulated Pedersen Commitment (cm_pedersen): {cm_pedersen_str[:10]}...")
        except Exception as e:
            logging.error(f"Failed simulated Pedersen commit: {e}")
            raise

        # 1b. Simulate VRF (based on the simulated Pedersen cm string)
        timestamp = str(int(time.time())); nonce = str(uuid.uuid4())
        sid = self.crypto.hash(f"{self.address}|{timestamp}|{nonce}")
        hash_input_vrf = self.crypto.hash(f"{cm_pedersen_str}|{sid}") # VRF depends on Pedersen cm
        logging.debug(f"  hashInput (for VRF, based on cm_pedersen_str): {hash_input_vrf}")
        vrf_output, pi_vrf = None, None
        try:
            vrf_output, pi_vrf = self.crypto.simulate_generate_vrf(self.vrf_private_key, hash_input_vrf)
            logging.info(f"  VRF Output (Simulated): {vrf_output.hex()[:10]}...")
        except Exception as e:
            logging.error(f"Failed VRF simulation: {e}")
            raise
        # --- End of Pedersen/VRF specific part ---


        # --- Prepare inputs for ZKP pi_1 (age_id circuit based on Poseidon) ---
        logging.info("  Preparing inputs for ZK proof pi_1 (age_id circuit)...")

        # 2a. Calculate id_hash (Private Input for ZKP)
        # Use hash_data_for_circuit as it's likely designed to produce ZKP-friendly field elements
        calculated_id_hash = None
        try:
            calculated_id_hash = hash_data_for_circuit(id_str)
            logging.info(f"  Calculated id_hash (for ZKP): {calculated_id_hash[:10]}...")
        except Exception as e:
            logging.error(f"Failed to calculate id_hash: {e}")
            raise

        # 2b. Generate r for Poseidon commitment (Private Input for ZKP)
        r_poseidon_hex = self.crypto.generate_random_r(64)
        r_poseidon_str = str(int(r_poseidon_hex, 16))
        logging.info(f"  Generated r_poseidon (for ZKP): {r_poseidon_str[:10]}...")

        # 2c. Calculate Poseidon Commitment: cm = Poseidon(age, id_hash, r_poseidon) (Public Input for ZKP)
        calculated_cm_poseidon = None
        try:
            # Use the specific Poseidon function for ZKP commitments
            poseidon_inputs_for_cm = [age_str, calculated_id_hash, r_poseidon_str]
            calculated_cm_poseidon = self.crypto.poseidon_commit_for_zkp(poseidon_inputs_for_cm)
            logging.info(f"  Calculated Poseidon Commitment cm (Public Input for ZKP): {calculated_cm_poseidon[:10]}...")
        except Exception as e:
            logging.error(f"Failed Poseidon commit for ZKP 'cm': {e}")
            raise

        # 3. Construct inputs for generate_witness_and_proof based on AgeIdCheck.circom
        #    *** This now matches the circuit definition ***
        pi1_inputs = {
            # Private Inputs matching AgeIdCheck.circom:
            "age": age_str,                  # circuit: signal input age;
            "id_hash": calculated_id_hash,   # circuit: signal input id_hash;
            "r": r_poseidon_str,             # circuit: signal input r; (for Poseidon cm)
            # Public Inputs matching AgeIdCheck.circom:
            "cm": calculated_cm_poseidon     # circuit: signal input cm; (Poseidon commitment)
        }
        logging.debug(f"  Inputs prepared for age_id ZKP: {pi1_inputs}")


        # 4. Generate ZK-SNARK pi_1 using the correct inputs
        logging.info("  Generating ZK proof pi_1 (age_id)...")
        pi_1, public_signals_pi1 = None, None
        try:
            pi_1, public_signals_pi1 = generate_witness_and_proof('age_id', pi1_inputs)

            # Verify the returned public signal matches the calculated Poseidon 'cm'
            if not public_signals_pi1 or str(public_signals_pi1[0]) != str(calculated_cm_poseidon):
                logging.error(f"ZKP pi_1 public signal mismatch! Expected Poseidon cm {calculated_cm_poseidon}, got {public_signals_pi1}")
                # Decide if this should raise an error or just log a warning
                # For now, raising an error is safer
                raise ValueError("ZKP pi_1 public signal mismatch after generation.")
            else:
                 logging.info(f"  ZK proof pi_1 generated successfully. Public signal matches expected cm: {public_signals_pi1[0]}")

        except subprocess.CalledProcessError as e:
            # Log detailed error info if snarkjs fails
            logging.error(f"Failed ZK proof pi_1 generation: snarkjs command failed!")
            logging.error(f"Return Code: {e.returncode}")
            logging.error(f"Command: {' '.join(e.cmd)}")
            # Decode stdout/stderr if they are bytes
            stdout = e.stdout.decode('utf-8', errors='replace') if isinstance(e.stdout, bytes) else e.stdout
            stderr = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else e.stderr
            logging.error(f"Stdout: {stdout}")
            logging.error(f"Stderr: {stderr}")
            logging.error(f"Input data passed to generate_witness_and_proof: {pi1_inputs}") # Log inputs on error
            raise # Re-raise the specific error
        except Exception as e:
            # Catch other potential errors during proof generation
            logging.error(f"Failed ZK proof pi_1 generation: {e}")
            logging.error(traceback.format_exc()) # Log full traceback
            logging.error(f"Input data passed to generate_witness_and_proof: {pi1_inputs}") # Log inputs on error
            raise


        # 5. Package results - Include both Pedersen/VRF and Poseidon/ZKP info if needed downstream
        self.identity_package = {
            # Pedersen Commitment related (potentially for Issuer interaction/VRF)
            'cm_pedersen': cm_pedersen_str,
            'r_pedersen_hex': r_pedersen_hex, # Store the Pedersen r if needed

            # VRF related (based on cm_pedersen)
            'pi_vrf': pi_vrf,
            'vrf_output': vrf_output,
            'hash_input': hash_input_vrf,
            'user_vrf_public_key': self.vrf_public_key,

            # Poseidon Commitment related (used in ZKP pi_1)
            'cm_poseidon': calculated_cm_poseidon, # The public input for pi_1
            'id_hash_for_zkp': calculated_id_hash, # The private input id_hash
            'r_poseidon_for_zkp': r_poseidon_str,  # The private input r

            # ZKP pi_1 (proves age>18 and knowledge for cm_poseidon)
            'pi_1': pi_1,
            'public_signals_pi1': public_signals_pi1 # Should contain cm_poseidon
        }
        logging.info(f"{self.__class__.__name__}: Identity package prepared successfully.")
        return self.identity_package



    # ***** 新增: 实现 Alg 2 流程 *****
    def request_credential(self, issuer):
        """ Implements Algorithm 2 flow using PLACEHOLDER ZKP pi_2 """
        if self.credential_path and os.path.exists(self.credential_path): logging.info(f"{self.__class__.__name__}: Credential exists."); return True
        logging.info(f"{self.__class__.__name__} ({self.address[:8]}...): Requesting credential from Issuer...")
        if self.user_id_details is None or self.age is None: logging.error("Identity not set."); return False
        if self.identity_package is None: logging.error("Identity package (pi_1) not prepared."); return False

        # 1. Generate sk, r1, r2, t
        sk_str = hash_data_for_circuit(self.user_id_details); t_int = int(time.time()); t_str = str(t_int)
        r1_hex = self.crypto.generate_random_r(64); r1_str = str(int(r1_hex, 16))
        r2_hex = self.crypto.generate_random_r(64); r2_str = str(int(r2_hex, 16))
        # 2. Compute C = Poseidon(sk, r1) + Poseidon(t, r2)
        try:
            h1 = self.crypto.poseidon_commit_for_zkp([sk_str, r1_str]); h2 = self.crypto.poseidon_commit_for_zkp([t_str, r2_str])
            params = self.crypto.get_pedersen_params(); p = params.get('p')
            if not p: raise ValueError("Modulus P not available")
            C_int = (int(h1) + int(h2)) % p ; C_str = str(C_int)
            logging.info(f"  Calculated credential commitment C = {C_str[:10]}...")
        except Exception as e: logging.error(f"Failed credential commitment C calc: {e}"); return False
        # 3. Send C to Issuer, get Merkle Root T and Proof Path/Indices
        try:
            merkle_root_bytes, path_elements_str, path_indices = issuer.process_credential_commitment(C_str)
            if merkle_root_bytes is None: raise RuntimeError("Issuer failed to process commitment.")
            merkle_root_T_str = str(int.from_bytes(merkle_root_bytes, 'big'))
            logging.info(f"  Received Merkle Root T = {merkle_root_T_str[:10]}... Path elements = {len(path_elements_str)}")
        except Exception as e: logging.error(f"Failed get Merkle info: {e}"); return False

        # 4. Generate ZKP pi_2 (using placeholder circuit)
        logging.info("  Generating ZK proof pi_2 (credential_check - placeholder)...")
        # ***** 修改: 输入匹配占位符电路 *****
        pi2_inputs = {
            # Private Inputs
            "sk": sk_str, "t": t_str, "r1": r1_str, "r2": r2_str,
            # Public Inputs
            "C": C_str
            # Merkle path inputs not needed for placeholder circuit witness
        }
        # ***** 修改结束 *****
        try:
            pi_2, public_signals_pi2 = generate_witness_and_proof('credential_check', pi2_inputs)
            if not public_signals_pi2 or str(public_signals_pi2[0]) != C_str: logging.warning(f"ZKP pi_2 public signal mismatch!")
            logging.info("  ZK proof pi_2 (placeholder) generated.")
        except Exception as e: logging.error(f"Failed ZK proof pi_2 generation: {e}"); return False

        # 5. Send (pi_2, T) to Issuer for verification
        logging.info("  Sending pi_2 and Merkle Root T to Issuer for verification...")
        try:
            # Issuer 验证 pi_2 (占位符) - T 在这里仅用于日志或未来扩展
            pi2_verification_ok = issuer.verify_credential_proof(pi_2, merkle_root_bytes, C_str)
            if not pi2_verification_ok: logging.error("Issuer failed pi_2 verification."); return False
            logging.info("Issuer verified pi_2 successfully.")
        except Exception as e: logging.error(f"Error during Issuer pi_2 verification: {e}"); return False

        # 6. Issuer issues final credential if pi_2 verifies
        logging.info("  Requesting final credential issuance from Issuer...")
        try:
            cm_pedersen_from_pkg = self.identity_package.get('cm_pedersen')
            if not cm_pedersen_from_pkg: logging.error("Missing cm_pedersen in stored package."); return False
            credential_data, credential_issuer_path = issuer.issue_credential( self.user_id_details, cm_pedersen_from_pkg, merkle_root_bytes )
            if credential_data and credential_issuer_path:
                 self.save_credential(credential_data)
                 logging.info(f"{self.__class__.__name__}: Credential request process completed successfully.")
                 return True
            else: logging.error("Issuer failed final credential issuance."); return False
        except Exception as e: logging.error(f"Error during final credential issuance: {e}"); return False

    def save_credential(self, credential_data):
        # ... (保持不变) ...
        if not credential_data: logging.error("Buyer: Invalid credential data."); return False
        try: timestamp = int(time.time()); addr_part = self.address.replace('0x','_')[:10]; filename = f"credential_{addr_part}_{timestamp}.json"; filepath = os.path.join(self.data_dir, filename); DataUtils.save_data(credential_data, filepath); self.credential_path = filepath; logging.info(f"Buyer: Credential saved to {filepath}"); return True
        except Exception as e: logging.error(f"Buyer: Failed to save credential: {e}"); return False

    # --- Transaction Initiation Response ---
    def acknowledge_transaction(self, tx_id, tx_id_bytes32, data_id, seller_address, htlc_hashes, t1, t2, t3, total_price_ether):
        logging.info(f"Buyer: Acknowledging transaction TxID {tx_id[:10]} for data '{data_id}'...")
        if tx_id in self.transactions: logging.warning("Transaction already acknowledged."); return

        price_per_layer = Decimal(str(total_price_ether)) / Decimal("3.0")

        self.transactions[tx_id] = {
            'tx_id_bytes32': tx_id_bytes32, 'data_id': data_id, 'seller_address': seller_address,
            'status': 'acknowledged', 'contract_status': 1,
            'htlc_hashes': htlc_hashes, 'htlc_timelocks': {'L1': t1, 'L2': t2, 'L3': t3},
            'price_per_layer': price_per_layer, 'htlc_locks': {},
            'layer_verification_confirmed': {'L1': False, 'L2': False, 'L3': False},
            'received_layers': set(), }
        tx_data_dir = os.path.join('data', 'buyer', f'tx_{tx_id}')
        os.makedirs(tx_data_dir, exist_ok=True)
        logging.info(f"  Transaction acknowledged. Price/Layer: {price_per_layer:.8f} ETH. Data dir: {tx_data_dir}")

    # --- Algorithm 5: HTLC Locking ---
    def lock_funds_for_layer(self, tx_id, layer_key):
        logging.info(f"Buyer: Locking funds via HTLC for {layer_key} (TxID {tx_id[:10]})...")
        if tx_id not in self.transactions: raise ValueError("Transaction not found.")
        tx_state = self.transactions[tx_id]
        if layer_key in tx_state['htlc_locks']: logging.warning(f"Funds for {layer_key} seem already locked."); return tx_state['htlc_locks'][layer_key]

        htlc_hash_hex = tx_state['htlc_hashes'][layer_key]
        time_lock_ts = tx_state['htlc_timelocks'][layer_key]
        amount_ether = tx_state['price_per_layer']
        seller_address = tx_state['seller_address']
        amount_str = f"{amount_ether:.18f}"

        try:
            logging.info(f"  Calling htlc.newLock with H={htlc_hash_hex[:10]}, T={time_lock_ts}, Amt={amount_str} ETH")
            receipt, lock_id_bytes32 = self.web3.htlc_new_lock( self.address, self.private_key, seller_address, htlc_hash_hex, time_lock_ts, amount_str )
            if lock_id_bytes32:
                 lock_id_hex = lock_id_bytes32.hex()
                 tx_state['htlc_locks'][layer_key] = lock_id_bytes32
                 logging.info(f"  HTLC lock for {layer_key} created successfully! LockID: {lock_id_hex[:10]}...")
                 self.update_balance()
                 return lock_id_bytes32
            else: logging.error(f"Failed to create HTLC lock for {layer_key} or retrieve LockID."); self.update_balance(); return None
        except Exception as e: logging.error(f"Error locking funds for {layer_key}: {e}"); self.update_balance(); return None

    # --- Algorithm 5 & 6: Verification & Confirmation ---
    # ***** 新增/修改: 分离链下验证 *****
     # ***** 修改: 添加详细日志 *****
    def verify_layer_package_offchain(self, tx_id, layer_package):
        """
        Buyer verifies received layer package (ZK proof, VTS signature) OFF-CHAIN.
        Returns True if valid, False otherwise. Also saves data on success.
        """
        layer_key = layer_package['layer']
        logging.info(f"Buyer: Verifying received package OFF-CHAIN for {layer_key} (TxID {tx_id[:10]})...")
        if tx_id not in self.transactions: logging.error(f"Transaction {tx_id} not found."); return False

        try:
            # 1. Verify ZK proof
            zk_proof = layer_package['zk_proof']
            public_signals = layer_package['public_signals']
            circuit_name = f"layer{int(layer_key[1])}"

            logging.info(f"--> [Off-chain Check 1/2] Verifying ZK proof '{circuit_name}'...")
            logging.debug(f"    Proof object: {json.dumps(zk_proof)}")
            logging.debug(f"    Public signals: {public_signals}")
            # 调用 snarkjs_utils 中的验证函数
            is_zkp_valid = verify_proof(circuit_name, zk_proof, public_signals)

            if not is_zkp_valid:
                logging.error(f"  [FAIL] ZK proof verification failed for {layer_key}!")
                return False
            logging.info(f"  [ OK ] ZK proof verification successful for {layer_key}.")

            # 2. Verify VTS signature
            layer_data = layer_package['data']
            vts_tuple = layer_package['vts']
            seller_rsa_public_key_str = layer_package['seller_rsa_public_key']
            seller_rsa_public_key_pem = seller_rsa_public_key_str.encode('utf-8')

            logging.info(f"--> [Off-chain Check 2/2] Verifying VTS signature for {layer_key}...")
            logging.debug(f"    VTS tuple: {vts_tuple}")
            logging.debug(f"    Seller RSA PubKey PEM: {seller_rsa_public_key_str[:50]}...")
            # 计算验证所需的 data hash
            layer_data_hash_hex = self.crypto.hash(layer_data)
            logging.debug(f"    Calculated Layer Data Hash (for VTS): 0x{layer_data_hash_hex}")
            # 调用 crypto_utils 中的验证函数
            # ***** 修改：调用正确的 VTS 验证函数名 *****
            is_vts_valid = self.crypto.verify_simplified_vts(
                 layer_data, # 传递原始数据或其 SHA256 哈希字符串均可，函数内部会处理
                 vts_tuple,
                 seller_rsa_public_key_pem
            )
            # ***** 修改结束 *****

            if not is_vts_valid:
                 logging.error(f"  [FAIL] VTS signature verification failed for {layer_key}!")
                 return False
            logging.info(f"  [ OK ] VTS signature verification successful for {layer_key}.")

            # 3. Store received data (only after ALL verifications passed)
            logging.info(f"--> Storing received {layer_key} data...")
            self.received_data_store.setdefault(tx_id, {})[layer_key] = layer_data
            save_path = os.path.join('data', 'buyer', f'tx_{tx_id}', f'{layer_key}_data.json')
            try:
                self.data_utils.save_data(layer_data, save_path)
                logging.info(f"  {layer_key} data saved to {save_path}")
            except Exception as e:
                logging.error(f"Failed to save {layer_key} data: {e}")
            tx_state = self.transactions[tx_id]
            tx_state['received_layers'].add(layer_key)

            logging.info(f"Buyer: Off-chain verification for {layer_key} completely successful.")
            return True # 所有检查都通过

        except Exception as e:
             # 捕获验证过程中的意外错误
             logging.error(f"Error during off-chain verification for {layer_key}: {e}")
             logging.error("详细错误信息:", exc_info=True) # 记录完整 traceback
             return False
    # ***** 修改结束 *****

    # ... (confirm_verification_onchain, decrypt_and_verify_l3, get_final_data, handle_htlc_refund 保持不变) ...
    # 注意: decrypt_and_verify_l3 内部调用的是 verify_layer_package_offchain，所以也会包含新日志

    # ***** 新增: 链上确认函数 (修正了调用的 web3 辅助函数名) *****
    def confirm_verification_onchain(self, tx_id, layer_key):
        """ Calls the correct data trading contract function ('confirmVerification') on chain via web3_utils wrapper """
        logging.info(f"Buyer: Confirming {layer_key} verification ON-CHAIN (TxID {tx_id[:10]})...")
        if tx_id not in self.transactions: raise ValueError("Transaction not found.")
        tx_state = self.transactions[tx_id]
        # 检查是否已链下验证通过 (通过 received_layers 判断)
        if layer_key not in tx_state['received_layers']:
            logging.error(f"Cannot confirm verification for {layer_key} on chain, layer not received/verified off-chain.")
            return False
        if tx_state['layer_verification_confirmed'][layer_key]:
            logging.warning(f"{layer_key} verification already confirmed on chain.")
            return True

        layer_index_map = {'L1': 0, 'L2': 1, 'L3': 2}
        if layer_key not in layer_index_map:
            logging.error(f"Invalid layer key provided: {layer_key}")
            return False

        tx_id_bytes32 = tx_state.get('tx_id_bytes32')
        if not tx_id_bytes32:
            logging.error(f"Missing tx_id_bytes32 in transaction state for {tx_id}")
            return False

        try:
            # ***** 重要修改: 调用修正后的 web3 工具函数名 *****
            # 假设你在 web3_utils.py 中创建/重命名了一个函数 dt_confirm_verification
            # 这个函数内部应该调用合约的 contract.functions.confirmVerification(...).transact({...})
            receipt = self.web3.dt_confirm_verification(  # <--- RENAMED WRAPPER FUNCTION CALL
                self.address,
                self.private_key,
                tx_id_bytes32,
                layer_index_map[layer_key]
            )
            # ***** 修改结束 *****

            # 检查回执是否成功 (根据你的 web3_utils 实现可能需要调整)
            if receipt and receipt.get('status') == 1:
                # 标记本地状态
                tx_state['layer_verification_confirmed'][layer_key] = True
                # 获取并更新合约状态 (调用 dt_get_transaction_status 是正确的)
                current_contract_status = self.web3.dt_get_transaction_status(tx_id_bytes32)
                tx_state['contract_status'] = current_contract_status
                status_map = {0:"Init", 1:"Active", 2:"L1_Verified", 3:"L2_Verified", 4:"Completed", 5:"Cancelled"}
                local_status_map = {2:"l1_verified", 3:"l2_verified", 4:"completed"} # 本地状态映射可能需要调整
                # 更新本地状态以匹配合约状态（如果适用）
                if current_contract_status in local_status_map:
                    tx_state['status'] = local_status_map[current_contract_status]

                logging.info(f"  [ OK ] {layer_key} verification confirmed on chain. Tx Status: {tx_state['status']} (Contract: {status_map.get(current_contract_status, 'Unknown')})")
                self.update_balance() # 更新余额（扣除 gas 费）
                return True
            else:
                logging.error(f"  [FAIL] On-chain confirmation transaction failed or receipt invalid for {layer_key}.")
                # 可选: 尝试读取合约状态以了解失败原因
                try:
                    layer_details = self.web3.dt_get_layer_details(tx_id_bytes32, layer_index_map[layer_key])
                    logging.info(f"    Current layer details on-chain: delivered={layer_details[2]}, verified={layer_details[3]}")
                    if not layer_details[2]:
                         logging.warning("    Possible reason: Seller has not confirmed delivery on-chain yet (delivered flag is false).")
                except Exception as detail_err:
                    logging.warning(f"    Could not fetch layer details: {detail_err}")
                self.update_balance()
                return False

        except Exception as e:
            logging.error(f"  [ERROR] Exception during on-chain confirmation call for {layer_key}: {e}")
            # 检查是否包含 revert 信息
            if 'revert' in str(e).lower():
                logging.error("  Transaction likely reverted. Check contract requirements (e.g., 'Layer not delivered'?) or Ganache/node logs.")
            elif "The function 'dt_confirm_verification' was not found" in str(e):
                 logging.error("  >>> You still need to rename/create the 'dt_confirm_verification' function in your web3_utils.py <<<")
            elif "The function 'confirmVerification' was not found" in str(e):
                 logging.error("  >>> Problem might be in the ABI file used by web3_utils. Ensure it's up-to-date. <<<")

            self.update_balance()
            return False
        
    # ***** 修改: 调用新的链下验证函数 *****
    def decrypt_and_verify_l3(self, tx_id, encrypted_package):
        """Decrypts L3 data and performs off-chain verification steps."""
        layer_key = 'L3'
        logging.info(f"Buyer: Decrypting and verifying received package for {layer_key} (TxID {tx_id[:10]})...")
        if tx_id not in self.transactions: raise ValueError("Transaction not found.")
        tx_state = self.transactions[tx_id]
        # Check if already successfully processed off-chain
        if layer_key in tx_state['received_layers']:
             logging.warning(f"  Layer {layer_key} already processed and verified off-chain.")
             return True # Indicate success as off-chain part is done

        # 1. Decrypt L3 data
        encrypted_data_chunks = encrypted_package['encrypted_data']
        logging.info("  Decrypting L3 data...")
        try:
            decrypted_l3_data = self.crypto.decrypt_data(encrypted_data_chunks, self.rsa_private_key)
            logging.info("  L3 decryption successful.")
        except Exception as e:
            logging.error(f"  L3 decryption failed: {e}")
            return False # Cannot proceed

        # 2. Prepare package for off-chain verification
        layer_package_l3 = {
            'layer': layer_key,
            'data': decrypted_l3_data, # 使用解密后的数据
            'zk_proof': encrypted_package['zk_proof'],
            'public_signals': encrypted_package['public_signals'],
            'vts': encrypted_package['vts'],
            'seller_rsa_public_key': encrypted_package['seller_rsa_public_key']
        }

        # 3. Perform off-chain verification using the separated function
        return self.verify_layer_package_offchain(tx_id, layer_package_l3)

    # --- 其他函数 ---
    def get_final_data(self, tx_id):
         if tx_id not in self.received_data_store:
             logging.info(f"No data received yet for TxID {tx_id[:10]}.")
             return None
         received = self.received_data_store[tx_id]
         if 'L3' in received: return received['L3']
         if 'L2' in received: return received['L2']
         if 'L1' in received: return received['L1']
         return None

    def handle_htlc_refund(self, tx_id, layer_key):
        logging.info(f"Buyer: Attempting HTLC refund for {layer_key} (TxID {tx_id[:10]})...")
        if tx_id not in self.transactions: raise ValueError("Transaction not found.")
        tx_state = self.transactions[tx_id]
        if layer_key not in tx_state.get('htlc_locks', {}): logging.error(f"HTLC Lock ID for {layer_key} not found."); return False
        lock_id = tx_state['htlc_locks'][layer_key]
        time_lock_ts = tx_state['htlc_timelocks'][layer_key]
        current_time = int(time.time())
        if current_time <= time_lock_ts + 60: logging.warning(f"Timelock for {layer_key} (T={time_lock_ts}) might not have expired yet (Current={current_time})."); # Allow attempt anyway
        try:
             receipt, success = self.web3.htlc_refund( self.address, self.private_key, lock_id )
             if success:
                 logging.info(f"  HTLC refund for {layer_key} successful!")
                 self.update_balance()
                 tx_state['status'] = f"{layer_key}_refunded"
                 return True
             else:
                  logging.error(f"  HTLC refund for {layer_key} failed on chain (or event not found).")
                  self.update_balance()
                  try:
                     status = self.web3.htlc_get_lock_status(lock_id); logging.info(f"  Current HTLC status: Withdrawn={status[5]}, Refunded={status[6]}, TimeLock={status[4]}, Now={current_time}")
                  except Exception as e: logging.warning(f"Could not fetch HTLC status: {e}")
                  return False
        except Exception as e: logging.error(f"  Error during HTLC refund call for {layer_key}: {e}"); self.update_balance(); return False
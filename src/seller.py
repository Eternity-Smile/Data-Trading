# backend/src/seller.py
import logging
import time
import uuid
import json
import os
from decimal import Decimal
import traceback
import subprocess
# 确保导入所有需要的模块和函数
try:
    from crypto_utils import CryptoUtils
    from web3_utils import Web3Utils
    from data_utils import DataUtils
    # 只从 snarkjs_utils 导入 ZKP 相关
    from snarkjs_utils import generate_witness_and_proof, hash_data_for_circuit, verify_proof
    # 从 crypto_utils 导入 Bn (如果 crypto_utils 定义了它 - 在 Petlib 可用时)
    # 但由于我们现在强制使用模拟，所以不需要导入 Bn
    # from crypto_utils import Bn
except ImportError as e: logging.error(f"Seller Import Error: {e}"); raise

class DataSeller:
    def __init__(self, address, private_key):
        if not private_key: raise ValueError("Seller requires private key.")
        self.address = address; self.private_key = private_key
        self.base_user_id = address
        self.user_id_details = None # Stores validated 18-digit ID string
        self.age = None
        self.credential_path = None
        self.identity_package = None # Store the prepared package
        self.data_dir = os.path.join('data', 'seller')
        os.makedirs(self.data_dir, exist_ok=True)
        logging.info(f"Initializing Seller: Addr={self.address}")

        self.crypto = CryptoUtils()
        self.web3 = Web3Utils()
        self.data_utils = DataUtils()

        self.rsa_private_key, self.rsa_public_key, self.vrf_private_key, self.vrf_public_key = self.crypto.generate_rsa_key_pair()
        self.rsa_public_key_str = self.rsa_public_key.decode('utf-8')
        self.vrf_public_key_pem = self.vrf_public_key # bytes

        self.data_catalog = {}
        self.transactions = {}
        try: self.balance = Decimal(self.web3.get_balance(self.address))
        except Exception as e: logging.warning(f"Seller init balance fetch failed: {e}"); self.balance = Decimal("0.0")
        logging.info(f"Seller Initial Balance: {self.balance:.8f} ETH")

    def update_balance(self):
        try: self.balance = Decimal(self.web3.get_balance(self.address)); logging.info(f"Seller Balance Updated: {self.balance:.8f} ETH")
        except Exception as e: logging.warning(f"Could not update seller balance: {e}")

    # --- 身份验证与凭证 ---
    # ***** 确保这个方法存在 *****
    def set_identity(self, age, id_str):
        """Sets and validates identity info format."""
        logging.info(f"Seller ({self.address[:8]}...): Setting identity Age={age}, ID={id_str}")
        if not isinstance(age, int) or not (18 < age < 150): logging.error("Invalid age (19-149)."); return False
        if not isinstance(id_str, str) or len(id_str) != 18 or not id_str.isdigit(): logging.error("Invalid ID: Must be 18 digits."); return False
        if not id_str.startswith("5001"): logging.error("Invalid ID: Must start with '5001'."); return False
        if id_str.endswith("00"): logging.error("Invalid ID: Last two digits cannot be '00'."); return False
        self.age = age; self.user_id_details = id_str
        logging.info("Seller identity information set and format validated.")
        return True
    # ***** 方法结束 *****

    # ***** 确保这个方法是最新版本 *****
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




    # ***** 函数结束 *****

    # ***** 确保这个方法存在 *****
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

    # ***** 确保这个方法存在 *****
    def save_credential(self, credential_data):
        """Saves issued credential to local file."""
        if not credential_data: logging.error("Seller: Invalid credential data."); return False
        try:
            timestamp = int(time.time()); addr_part = self.address.replace('0x','_')[:10]
            filename = f"credential_{addr_part}_{timestamp}.json"
            filepath = os.path.join(self.data_dir, filename)
            self.data_utils.save_data(credential_data, filepath) # Use static method
            self.credential_path = filepath
            logging.info(f"Seller: Credential saved to {filepath}")
            return True
        except Exception as e: logging.error(f"Seller: Failed to save credential: {e}"); return False
    # ***** 函数结束 *****

    # --- 其他函数保持不变 ---
    # ... (add_data_to_catalog, initiate_transaction, set_htlc_and_vts_params, deliver_layer_data, handle_htlc_withdraw, re_encrypt_and_deliver_l3) ...
    def add_data_to_catalog(self, data_id, data, description, price_ether):
        logging.info(f"Seller: Adding data '{data_id}' to catalog...")
        if data_id in self.data_catalog: raise ValueError(f"Data ID '{data_id}' exists")
        stratified_data = self.data_utils.stratify_data(data); layers = {'L1': stratified_data['L1'], 'L2': stratified_data['L2'], 'L3': stratified_data['L3']}
        commitments_zkp = {}; randomness_zkp = {}; layer_hashes_sha256 = {}; proofs = {}; public_signals = {}
        for i, layer_key in enumerate(['L1', 'L2', 'L3']):
            layer_index = i + 1; layer_content = layers[layer_key]; circuit_name = f"layer{layer_index}"
            layer_hash_hex_sha256 = self.crypto.hash(layer_content); layer_hashes_sha256[layer_key] = "0x" + layer_hash_hex_sha256
            layer_hash_for_circuit = hash_data_for_circuit(layer_content)
            r_hex = self.crypto.generate_random_r(64); r_str = str(int(r_hex, 16)); randomness_zkp[layer_key] = r_hex
            try: c_i = self.crypto.poseidon_commit_for_zkp([layer_hash_for_circuit, r_str]); commitments_zkp[layer_key] = c_i
            except Exception as e: logging.error(f"Failed Poseidon commit for {layer_key}: {e}"); raise
            logging.info(f"  {layer_key}: Hash(SHA256)={layer_hash_hex_sha256[:10]}..., R(ZKP)={r_hex[:10]}..., C(Poseidon)={c_i[:10]}...")
            logging.info(f"  Generating ZK proof {circuit_name}...")
            pi_li_inputs = { "layer_hash": layer_hash_for_circuit, "R": r_str, "C": c_i }
            try:
                pi_li, public_li = generate_witness_and_proof(circuit_name, pi_li_inputs)
                if not public_li or str(public_li[0]) != str(c_i): logging.warning(f"ZKP public signal mismatch for {layer_key}!")
                proofs[layer_key] = pi_li; public_signals[layer_key] = public_li
                logging.info(f"  ZK proof {circuit_name} generated.")
            except Exception as e: logging.error(f"Failed ZKP generation for {circuit_name}: {e}"); raise
        self.data_catalog[data_id] = { 'description': description, 'price_ether': Decimal(str(price_ether)), 'layers': layers,
            'randomness_for_zkp': randomness_zkp, 'commitments_for_zkp': commitments_zkp, 'layer_hashes_sha256': layer_hashes_sha256,
            'proofs': proofs, 'public_signals': public_signals, 'seller_rsa_public_key': self.rsa_public_key_str, 'created_at': time.time() }
        logging.info(f"Seller: Data '{data_id}' added successfully.")
        return data_id

    def initiate_transaction(self, data_id, buyer_address):
        logging.info(f"Seller: Initiating transaction for '{data_id}' with Buyer {buyer_address[:8]}...")
        if data_id not in self.data_catalog: raise ValueError(f"Data '{data_id}' not found.")
        try:
            receipt, tx_id_bytes32 = self.web3.dt_create_transaction(self.address, self.private_key, data_id, buyer_address)
            if not tx_id_bytes32: raise RuntimeError("Failed to create transaction or retrieve txId.")
            tx_id = tx_id_bytes32.hex(); logging.info(f"  Transaction created on-chain. TxID: {tx_id}")
            self.update_balance()
        except Exception as e: logging.error(f"Failed to initiate transaction: {e}"); self.update_balance(); raise
        self.transactions[tx_id] = { 'data_id': data_id, 'buyer_address': buyer_address, 'status': 'initiated', 'contract_status': 0,
            'tx_id_bytes32': tx_id_bytes32, 'htlc_params_set': False, 'htlc_locks': {},
            'layer_delivery_confirmed': {'L1': False, 'L2': False, 'L3': False},
            'vts': {}, 'htlc_preimages': {}, 'htlc_hashes': {} }
        return tx_id

    def set_htlc_and_vts_params(self, tx_id, t1, t2, t3):
        logging.info(f"Seller: Setting HTLC & VTS parameters for TxID {tx_id[:10]}...")
        if tx_id not in self.transactions: raise ValueError("Tx not found.")
        tx_state = self.transactions[tx_id]; data_id = tx_state['data_id']
        catalog_entry = self.data_catalog[data_id]
        htlc_hashes_dict = {}; vts_tuples = {}; preimages = {}
        for i, layer_key in enumerate(['L1', 'L2', 'L3']):
            layer_hash_hex_sha256 = catalog_entry['layer_hashes_sha256'][layer_key]
            h_i_hex_keccak, preimage_oi_bytes = self.crypto.generate_htlc_hash_and_preimage()
            htlc_hashes_dict[layer_key] = h_i_hex_keccak; preimages[layer_key] = preimage_oi_bytes
            logging.info(f"  {layer_key}: HTLC Hash(H{i+1})={h_i_hex_keccak[:10]}... (Keccak256)")
            vts_tuple = self.crypto.generate_simplified_vts(layer_hash_hex_sha256, h_i_hex_keccak, self.rsa_private_key)
            vts_tuples[layer_key] = vts_tuple
            logging.debug(f"  {layer_key}: VTS generated (Sig={vts_tuple['signature'][:10]}...)")
        tx_state['vts'] = vts_tuples; tx_state['htlc_preimages'] = preimages; tx_state['htlc_hashes'] = htlc_hashes_dict
        try:
            logging.info("  Registering HTLC params (T1-3, H1-3 Keccak) on DT contract...")
            h1_bytes = bytes.fromhex(htlc_hashes_dict['L1'][2:]); h2_bytes = bytes.fromhex(htlc_hashes_dict['L2'][2:]); h3_bytes = bytes.fromhex(htlc_hashes_dict['L3'][2:])
            receipt = self.web3.dt_set_transaction_params( self.address, self.private_key, tx_state['tx_id_bytes32'], t1, t2, t3, h1_bytes, h2_bytes, h3_bytes )
            tx_state['htlc_params_set'] = True; tx_state['status'] = 'params_set'; tx_state['contract_status'] = 1
            logging.info("  HTLC parameters registered on chain.")
            for i, layer_key in enumerate(['L1', 'L2', 'L3']):
                logging.info(f"  Registering {layer_key} info (DataHash SHA256 only) on chain...")
                commitment_placeholder = tx_state['tx_id_bytes32']
                data_hash_sha256_hex = catalog_entry['layer_hashes_sha256'][layer_key]
                self.web3.dt_register_layer_info( self.address, self.private_key, tx_state['tx_id_bytes32'], i, commitment_placeholder, data_hash_sha256_hex )
                logging.info(f"  {layer_key} info (DataHash) registered.")
            logging.info(f"Seller: HTLC & VTS setup complete for TxID {tx_id[:10]}.")
            self.update_balance()
            return htlc_hashes_dict
        except Exception as e: logging.error(f"Failed to set params/register info on chain: {e}"); self.update_balance(); raise

    def deliver_layer_data(self, tx_id, layer_key):
        logging.info(f"Seller: Delivering {layer_key} data and proof (off-chain) for TxID {tx_id[:10]}...")
        if tx_id not in self.transactions: raise ValueError("Tx not found.")
        tx_state = self.transactions[tx_id]; data_id = tx_state['data_id']
        catalog_entry = self.data_catalog[data_id]
        layer_data = catalog_entry['layers'][layer_key]; proof = catalog_entry['proofs'][layer_key]
        public_signals = catalog_entry['public_signals'][layer_key]; vts = tx_state['vts'][layer_key]
        commitment_c_zkp = catalog_entry['commitments_for_zkp'][layer_key]
        delivery_package = { 'layer': layer_key, 'data': layer_data, 'zk_proof': proof,
            'public_signals': public_signals, 'commitment_c_zkp': commitment_c_zkp,
            'vts': vts, 'seller_rsa_public_key': self.rsa_public_key_str }
        logging.info(f"  {layer_key} package prepared for off-chain delivery.")
        return delivery_package

# ***** 新增函数: 处理 L3 数据的加密和交付准备 (修正了公钥处理) *****
    def re_encrypt_and_deliver_l3(self, tx_id, buyer_public_key_str):
        """
        处理 L3 数据：使用买家的公钥对其进行加密。
        注意：这模拟了 Algorithm 6 中 L3 交付前的处理步骤，但使用了标准的非对称加密，
        而不是真正的代理重加密 (PRE)，因为 PRE 功能通常不直接可用。

        Args:
            tx_id (str): 交易 ID.
            buyer_public_key_str (str): 买家的 RSA 公钥字符串 (PEM 格式).

        Returns:
            list: 加密后的 L3 数据块列表 (准备发送给买家).
                  如果发生错误则返回 None.
        """
        logging.info(f"Seller: Preparing encrypted L3 package for TxID {tx_id[:10]}...")
        if tx_id not in self.transactions:
            logging.error(f"Transaction {tx_id} not found.")
            return None
        tx_state = self.transactions[tx_id]
        data_id = tx_state.get('data_id')
        if not data_id or data_id not in self.data_catalog:
            logging.error(f"Data ID not found in transaction state or catalog for TxID {tx_id}")
            return None

        catalog_entry = self.data_catalog[data_id]
        original_l3_data = catalog_entry['layers'].get('L3')
        if original_l3_data is None:
            logging.error(f"Original L3 data not found in catalog for data_id {data_id}")
            return None

        logging.info("  Encrypting L3 data using Buyer's public key...")
        try:
            # 1. 将买家的公钥字符串编码为字节串 (PEM 格式)
            #    不再需要调用不存在的 load_public_key 方法
            buyer_public_key_pem_bytes = buyer_public_key_str.encode('utf-8')
            logging.debug(f"  Buyer public key PEM (bytes): {buyer_public_key_pem_bytes[:70]}...") # 打印部分 PEM 字节

            # 2. 使用买家的公钥 PEM 字节串加密 L3 数据
            #    注意: encrypt_data 是 CryptoUtils 的静态方法
            encrypted_l3_chunks = CryptoUtils.encrypt_data(original_l3_data, buyer_public_key_pem_bytes)
            # 或者如果 self.crypto 实例确定存在，也可以用 self.crypto.encrypt_data(...)

            logging.info(f"  L3 data successfully encrypted into {len(encrypted_l3_chunks)} chunk(s).")

            # 3. 返回加密后的数据块列表
            return encrypted_l3_chunks # 返回加密后的数据

        except Exception as e:
            logging.error(f"  Error during L3 encryption process: {e}")
            logging.error(traceback.format_exc()) # 打印详细错误堆栈
            return None
# ***** 函数修改结束 *****

    def handle_htlc_withdraw(self, tx_id, layer_key):
        """ Seller attempts to withdraw HTLC funds using bytes32 preimage Oi."""
        logging.info(f"Seller: Attempting HTLC withdraw for {layer_key} (TxID {tx_id[:10]})...")
        if tx_id not in self.transactions: raise ValueError("Transaction not found.")
        tx_state = self.transactions[tx_id]
        if layer_key not in tx_state.get('htlc_locks', {}): logging.error(f"HTLC Lock ID for {layer_key} not found locally."); return False
        lock_id = tx_state['htlc_locks'][layer_key]
        preimage_oi_bytes32 = tx_state['htlc_preimages'].get(layer_key)
        if not preimage_oi_bytes32 or len(preimage_oi_bytes32) != 32: logging.error(f"Invalid preimage for {layer_key}"); return False

        withdraw_successful = False # Track HTLC withdraw success
        delivery_confirmed = False # Track DT confirmDelivery success

        try:
            # Step 1: Withdraw from HTLC
            receipt_htlc, success_htlc = self.web3.htlc_withdraw(
                self.address, # Seller is receiver in this context
                self.private_key,
                lock_id,
                preimage_oi_bytes32
            )
            if success_htlc:
                logging.info(f"  HTLC withdraw for {layer_key} successful!")
                withdraw_successful = True # Mark HTLC withdraw as successful
            else:
                # Log detailed status if withdraw failed
                logging.error(f"  HTLC withdraw for {layer_key} failed on chain (or event not found).")
                try:
                     status = self.web3.htlc_get_lock_status(lock_id)
                     logging.info(f"  Current HTLC status: Withdrawn={status[5]}, Refunded={status[6]}, TimeLock={status[4]}, Now={int(time.time())}")
                except Exception as e: logging.warning(f"Could not fetch HTLC status: {e}")
                # Keep withdraw_successful as False
        except Exception as e:
            logging.error(f"  Error during HTLC withdraw call for {layer_key}: {e}")
            # Check for specific revert reasons if possible
            if 'revert' in str(e).lower():
                 if 'invalid preimage' in str(e).lower(): logging.error("  Reason: Invalid Preimage provided to HTLC.")
                 elif 'timelock expired' in str(e).lower(): logging.error("  Reason: HTLC Timelock Expired.")
                 # Add check for V_t error if it were still in HTLC contract (it's not anymore)
                 # elif 'delivery time not signaled' in str(e).lower(): logging.error(" Reason: Delivery time not signaled in HTLC (Logic Error?).")
                 # elif 'verification interval not passed' in str(e).lower(): logging.error(" Reason: V_t interval not passed in HTLC (Logic Error?).")
            self.update_balance()
            return False # Exit if HTLC withdraw fails critically

        # Step 2: Confirm Delivery on DataTrading (only if HTLC withdraw succeeded)
        if withdraw_successful:
            layer_index_map = {'L1': 0, 'L2': 1, 'L3': 2}
            try:
                logging.info(f"  Attempting to confirm {layer_key} delivery on DataTrading contract (checks V_t)...")
                receipt_dt = self.web3.dt_confirm_layer_delivery(
                    self.address, self.private_key, tx_state['tx_id_bytes32'], layer_index_map[layer_key]
                )
                tx_state['layer_delivery_confirmed'][layer_key] = True
                delivery_confirmed = True # Mark DT confirmDelivery as successful
                logging.info(f"  Confirmed {layer_key} delivery on DataTrading contract.")
            except Exception as e:
                # Log specific V_t error if detected
                if 'revert' in str(e).lower() and 'verification interval not passed' in str(e).lower():
                     logging.warning(f"Failed confirm delivery for {layer_key}: Verification interval V_t has not passed yet.")
                else:
                     logging.warning(f"Failed confirm delivery on chain for {layer_key} after withdraw: {e}")
                # delivery_confirmed remains False

        self.update_balance() # Update balance regardless of confirmDelivery outcome
        # Return True only if BOTH HTLC withdraw AND Delivery Confirmation succeeded
        # ***** 修改: 返回值依赖于两个步骤 *****
        # return withdraw_successful and delivery_confirmed
        # 修正：即使 confirmDelivery 失败 (例如 V_t 未到)，只要 HTLC 提款成功，
        # Seller 就算完成了他的主要动作（拿到了钱），流程应该可以继续，
        # Buyer 后续的 confirmVerification 会因为 delivered=false 而失败。
        # 所以，我们应该返回 withdraw_successful 的结果。
        # 让 main.py 根据 Buyer 验证 和 Seller withdraw 状态决定后续。
        return withdraw_successful
        # ***** 修改结束 *****

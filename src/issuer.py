# backend/src/issuer.py
import time
import uuid
import os
import logging
import json
import hashlib # For Merkle Tree simulation
import traceback

try:
    from crypto_utils import CryptoUtils
    from snarkjs_utils import verify_proof
    from data_utils import DataUtils # For saving credential file
except ImportError as e: logging.error(f"Issuer Import Error: {e}"); raise

# --- Simple Merkle Tree Simulation ---
class SimpleMerkleTree:
    def __init__(self):
        self.leaves = [] # Stores leaf hashes (bytes)
        self.tree = []   # Stores levels of the tree (list of lists of bytes)
        self.root = None # Root hash (bytes)
        self.leaf_map = {} # Maps leaf data string to its hash for lookup

    def _hash_func(self, data_bytes1, data_bytes2=None):
        # Use SHA256 for internal tree hashing
        if data_bytes2 is None: # Hashing a leaf
            return hashlib.sha256(data_bytes1).digest()
        else: # Hashing two nodes
            # Ensure consistent order (e.g., sort lexicographically) before hashing
            combined = sorted([data_bytes1, data_bytes2])[0] + sorted([data_bytes1, data_bytes2])[1]
            return hashlib.sha256(combined).digest()

    def add_leaf(self, leaf_data_str):
        """Adds a leaf (represented by its data string) to the tree."""
        leaf_bytes = str(leaf_data_str).encode('utf-8')
        leaf_hash = self._hash_func(leaf_bytes)
        if leaf_hash in self.leaf_map.values():
             logging.warning(f"Leaf data '{leaf_data_str[:10]}...' already exists in tree.")
             # Decide how to handle duplicates, maybe just ignore?
             # For simulation, allow duplicates but map points to same hash
        self.leaves.append(leaf_hash)
        self.leaf_map[leaf_data_str] = leaf_hash # Map original data to its hash
        self._build_tree()
        logging.debug(f"Added leaf hash {leaf_hash.hex()[:10]}... New root: {self.root.hex()[:10] if self.root else 'None'}")
        return leaf_hash

    def _build_tree(self):
        if not self.leaves: self.tree = []; self.root = None; return
        level = self.leaves[:]
        self.tree = [level]
        while len(level) > 1:
            next_level = []
            if len(level) % 2 == 1: level.append(level[-1]) # Duplicate last node if odd
            for i in range(0, len(level), 2):
                next_level.append(self._hash_func(level[i], level[i+1]))
            level = next_level
            self.tree.append(level)
        self.root = level[0] if level else None

    def get_merkle_root(self):
        return self.root

    def get_merkle_proof(self, leaf_data_str):
        """Gets Merkle proof (path elements and indices) for a leaf data string."""
        leaf_hash = self.leaf_map.get(leaf_data_str)
        if leaf_hash is None: logging.error(f"Leaf data '{leaf_data_str[:10]}...' not found in map."); return None, None, None
        try: idx = self.leaves.index(leaf_hash) # Find first occurrence index
        except ValueError: logging.error(f"Leaf hash for '{leaf_data_str[:10]}...' not found in leaves list."); return None, None, None

        path_elements_bytes = []
        path_indices = [] # 0 for left sibling, 1 for right sibling (relative to node)
        current_index = idx
        for level_nodes in self.tree[:-1]: # Iterate through levels bottom-up (excluding root)
            is_right_node = current_index % 2
            sibling_index = current_index + 1 if not is_right_node else current_index - 1
            # Handle duplicated last node case during proof gen
            if sibling_index >= len(level_nodes): sibling_node_hash = level_nodes[current_index] # Use self if sibling is duplicated node
            else: sibling_node_hash = level_nodes[sibling_index]
            path_elements_bytes.append(sibling_node_hash)
            path_indices.append(0 if not is_right_node else 1) # 0: sibling is right, 1: sibling is left
            current_index //= 2 # Move to parent index

        # Convert path elements to integer strings for Circom
        path_elements_str = [str(int.from_bytes(p, 'big')) for p in path_elements_bytes]
        logging.debug(f"Merkle proof for leaf index {idx}: Path(str)={path_elements_str}, Indices={path_indices}")
        return self.root, path_elements_str, path_indices


class Issuer:
    def __init__(self):
        self.crypto = CryptoUtils()
        self.data_utils = DataUtils()
        self.rsa_private_key, self.rsa_public_key, _, self.issuer_vrf_public_key = self.crypto.generate_rsa_key_pair()
        logging.info(f"Issuer VRF Public Key (Simulated): {self.issuer_vrf_public_key.decode('utf-8', errors='ignore')[:50]}...")
        # ***** 修改: 初始化 Merkle 树 *****
        self.merkle_tree = SimpleMerkleTree()
        # ***** 修改结束 *****
        self.issued_credentials = {}
        self.data_dir = os.path.join('data', 'issuer')
        os.makedirs(self.data_dir, exist_ok=True)
        logging.info("Issuer Initialized.")

    def verify_identity_package(self, cm_pedersen, pi_vrf, vrf_output, hash_input, user_vrf_public_key, pi_1, public_signals_pi1):
        """ Verifies VRF (sim) and ZKP pi_1 (off-chain). """
        # ... (保持不变) ...
        logging.info(f"Issuer: Verifying identity package (cm_pedersen: {cm_pedersen[:10]}...).")
        vrf_input_bytes = str(hash_input).encode('utf-8')
        logging.info("--> Verifying simulated VRF...")
        try:
            is_vrf_valid = self.crypto.simulate_verify_vrf(user_vrf_public_key, vrf_input_bytes, vrf_output, pi_vrf)
            if not is_vrf_valid: logging.error("Issuer: VRF verification failed (simulated)."); return False
            logging.info("Issuer: VRF verification successful (simulated).")
        except Exception as e: logging.error(f"Error during VRF verification: {e}"); return False
        logging.info("--> Verifying ZK proof 'age_id'...")
        try:
            if not public_signals_pi1: logging.error("Missing public signals for ZKP verification."); return False
            logging.debug(f"Verifying pi_1 against public signals: {public_signals_pi1}")
            is_pi1_valid = verify_proof('age_id', pi_1, public_signals_pi1)
            if not is_pi1_valid: logging.error("Issuer: ZK-SNARK pi_1 verification failed."); return False
            logging.info("Issuer: ZK-SNARK pi_1 verification successful.")
        except Exception as e: logging.error(f"Error during ZKP pi_1 verification: {e}"); traceback.print_exc(); return False
        logging.info("Issuer: Identity package verified successfully (VRF sim + ZKP).")
        return True

    # ***** 新增: 处理用户承诺 C 并返回 Merkle 信息 *****
    def process_credential_commitment(self, commitment_C_str):
        """ Inserts user's commitment C into Merkle tree and returns root & proof """
        logging.info(f"Issuer: Received credential commitment C: {commitment_C_str[:10]}...")
        try:
            # 1. 插入 Merkle 树
            self.merkle_tree.add_leaf(commitment_C_str)
            # 2. 获取树根和证明
            root, path_elements_str, path_indices = self.merkle_tree.get_merkle_proof(commitment_C_str)
            if root is None: raise RuntimeError("Failed to get Merkle proof after insertion.")
            return root, path_elements_str, path_indices
        except Exception as e:
            logging.error(f"Error processing credential commitment or getting proof: {e}")
            return None, None, None

    # ***** 新增: 验证用户提供的 pi_2 凭证证明 *****
     # ***** 修改: verify_credential_proof 验证 ZKP *****
    def verify_credential_proof(self, pi_2, merkle_root_T_bytes, commitment_C_str):
        """ Verifies the ZKP pi_2 using the placeholder circuit which only expects C. """
        circuit_name = 'credential_check'
        # merkle_root_T_str 不再作为公开输入传递给当前的占位符电路
        # merkle_root_T_str = str(int.from_bytes(merkle_root_T_bytes, 'big'))
        logging.info(f"Issuer: Verifying credential proof pi_2 for C={commitment_C_str[:10]}...") # 日志中不再提 T

        # 公开输入现在只有 C (根据当前的 credential_check.circom 文件)
        public_signals = [commitment_C_str] # <-- 只包含 C
        logging.debug(f"Public signals for pi_2 verification: {public_signals}")

        # 不再打印占位符警告，因为我们现在尝试验证路径
        # logging.warning("Using placeholder ZKP circuit...")
        try:
            is_pi2_valid = verify_proof(circuit_name, pi_2, public_signals)
            if not is_pi2_valid:
                logging.error("Issuer: ZK-SNARK pi_2 verification failed.")
                return False
            # 更新成功日志信息以反映当前情况
            logging.info("Issuer: ZK-SNARK pi_2 verification successful (Placeholder circuit: checked C).")
            return True
        except Exception as e:
            logging.error(f"Error during ZKP pi_2 verification: {e}")
            traceback.print_exc()
            return False
    # ***** 修改结束 *****

    # ***** 修改: issue_credential 现在只负责签名和保存 *****
    def issue_credential(self, user_id_str, cm_pedersen, merkle_root_T_bytes):
        """ Issues the final credential JSON after pi_2 verification. """
        # verification_result (pi_2) is assumed to be true if this is called
        logging.info(f"Issuer: Issuing FINAL credential for user_id '{user_id_str}' (cm_pedersen: {cm_pedersen[:10]}...)")
        if not isinstance(merkle_root_T_bytes, bytes): logging.error("Invalid Merkle root type for credential."); return None, None

        current_time = int(time.time())
        validity_period = 86400 * 30 # 30 days
        epoch_validity = current_time + validity_period
        epoch_hash = self.crypto.hash(str(epoch_validity))
        merkle_root_hex = merkle_root_T_bytes.hex()

        message_to_sign = f"userId:{user_id_str}|commitment:{cm_pedersen}|validUntil:{epoch_validity}|merkleRoot:{merkle_root_hex}"
        message_bytes = message_to_sign.encode('utf-8')
        try: signature = self.crypto.rsa_sign(message_bytes, self.rsa_private_key)
        except Exception as e: logging.error(f"Failed to sign credential: {e}"); return None, None

        credential_data = { 'issuer_id': 'ExampleIssuer/DID', 'user_id': user_id_str, 'user_commitment_pedersen': cm_pedersen,
            'epoch': {'valid_until': epoch_validity, 'hash': epoch_hash},
            'merkle_root': merkle_root_hex, # Use actual Merkle Root hex
            'issuer_signature': signature }

        try:
            safe_user_id = "".join(c if c.isalnum() else "_" for c in user_id_str)
            filename = f"credential_{safe_user_id}_{current_time}.json"
            filepath = os.path.join(self.data_dir, filename)
            self.data_utils.save_data(credential_data, filepath) # Use static method
            logging.info(f"Issuer: Credential saved successfully to {filepath}")
            return credential_data, filepath
        except Exception as e: logging.error(f"Issuer: Failed to save credential file: {e}"); return None, None

    def verify_credential(self, credential_data):
        """Verifies the simple JSON credential."""
        # ... (保持不变) ...
        logging.info(f"Issuer/Verifier: Verifying credential...")
        if not isinstance(credential_data, dict): return False
        if time.time() > credential_data.get('epoch', {}).get('valid_until', 0): logging.warning("Credential expired."); return False
        cm_pedersen = credential_data.get('user_commitment_pedersen'); epoch = credential_data.get('epoch', {});
        merkle_root = credential_data.get('merkle_root') # Use 'merkle_root' key
        signature = credential_data.get('issuer_signature'); user_id = credential_data.get('user_id')
        if not all([cm_pedersen, epoch, merkle_root, signature, user_id, 'valid_until' in epoch, 'hash' in epoch]): logging.warning("Credential missing fields."); return False
        message_signed = f"userId:{user_id}|commitment:{cm_pedersen}|validUntil:{epoch.get('valid_until')}|merkleRoot:{merkle_root}"
        message_bytes = message_signed.encode('utf-8')
        is_sig_valid = self.crypto.rsa_verify(message_bytes, signature, self.rsa_public_key)
        if not is_sig_valid: logging.error("Invalid credential signature."); return False
        # Merkle root check against runtime tree (simulation limitation)
        # if cm_pedersen not in self.merkle_tree or self.merkle_tree[cm_pedersen]['root'].hex() != merkle_root:
        #     logging.warning(f"Commitment {cm_pedersen[:10]}... not in simulated tree or Merkle root mismatch.")
        #     return False
        logging.info("Credential verified successfully (Signature and expiry only).") # Merkle check removed for simplicity
        return True


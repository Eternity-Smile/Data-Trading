# backend/src/crypto_utils.py
import hashlib
import json
import random
import string
import time
import os
import logging

# 确保导入 Crypto 相关库
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    import base64
except ImportError as e:
    logging.error("PyCryptodome library not found. Please run 'pip install pycryptodome'.")
    raise e

# 移除 Petlib 导入

# 使用模运算参数
P_MOD = 115792089237316195423570985008687907853269984665640564039457584007908834671663
G_MOD = 2
H_MOD = 3
logging.info("Using MODULAR ARITHMETIC simulation for Pedersen commitments.")

# 尝试导入 snarkjs_utils 中的 poseidon_hash
try:
    from snarkjs_utils import poseidon_hash
except ImportError:
    logging.warning("Could not import poseidon_hash from snarkjs_utils.")
    def poseidon_hash(*args, **kwargs):
        logging.error("Poseidon hash function unavailable!"); raise NotImplementedError("Poseidon unavailable")

class CryptoUtils:

    # ***** 开始修改: 将 encrypt/decrypt 移入类并设为静态方法 *****
    @staticmethod
    def encrypt_data(data, public_key_pem):
        """Encrypts data using RSA public key (PEM format)."""
        logging.debug("Encrypting data with RSA public key...")
        try:
            key = RSA.import_key(public_key_pem)
            # Session key size limitation not applicable here as we use direct RSA encryption
            cipher_rsa = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            # Data needs to be bytes and chunked
            if isinstance(data, (dict, list)): data_bytes = json.dumps(data).encode('utf-8')
            elif isinstance(data, str): data_bytes = data.encode('utf-8')
            elif isinstance(data, bytes): data_bytes = data
            else: data_bytes = str(data).encode('utf-8')

            # RSA block size depends on key size and padding scheme (OAEP+SHA256 uses more overhead)
            # For 2048-bit key: key_size_bytes = 256. Max data = 256 - 2*32 - 2 = 190 bytes
            key_size_bytes = key.size_in_bytes()
            hash_len = SHA256.digest_size
            block_size = key_size_bytes - 2 * hash_len - 2
            if block_size <= 0: raise ValueError("Key size too small for OAEP padding.")
            logging.debug(f"RSA encryption block size: {block_size}")

            encrypted_chunks = []
            for i in range(0, len(data_bytes), block_size):
                chunk = data_bytes[i:i+block_size]
                encrypted_chunk = cipher_rsa.encrypt(chunk)
                encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
            logging.debug(f"Encrypted data into {len(encrypted_chunks)} chunks.")
            return encrypted_chunks # Return list of base64 encoded chunks
        except Exception as e: logging.error(f"RSA encryption failed: {e}"); raise

    @staticmethod
    def decrypt_data(encrypted_chunks, private_key_pem):
        """Decrypts data using RSA private key (PEM format)."""
        logging.debug(f"Decrypting {len(encrypted_chunks)} chunks with RSA private key...")
        try:
            key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            decrypted_bytes = b''
            for chunk_b64 in encrypted_chunks:
                encrypted_chunk = base64.b64decode(chunk_b64.encode('utf-8'))
                decrypted_bytes += cipher_rsa.decrypt(encrypted_chunk)
            logging.debug("Decryption successful, attempting to decode...")
            # Try to decode as JSON, fallback to text, then return bytes
            try: return json.loads(decrypted_bytes.decode('utf-8'))
            except json.JSONDecodeError:
                try: return decrypted_bytes.decode('utf-8')
                except UnicodeDecodeError: logging.warning("Decrypted data not valid UTF-8, returning bytes."); return decrypted_bytes
        except Exception as e: logging.error(f"RSA decryption failed: {e}"); raise
    # ***** 修改结束 *****


    @staticmethod
    def get_pedersen_params():
        """Returns parameters needed for Pedersen commit simulation"""
        return {"p": P_MOD, "g": G_MOD, "h": H_MOD}

    @staticmethod
    def simulated_pedersen_commit(message_parts, r_hex):
        """计算模拟的 Pedersen 承诺 cm = g^m * h^r mod p"""
        logging.debug(f"Calculating simulated Pedersen commitment for parts: {message_parts}")
        params = CryptoUtils.get_pedersen_params()
        p = params["p"]; g = params["g"]; h = params["h"]
        message_str = "|".join(map(str, message_parts))
        m_int = int(CryptoUtils.hash(message_str), 16) % p
        try: r_int = int(r_hex, 16)
        except ValueError: raise ValueError("Invalid hex format for randomness r")
        logging.debug(f"  Simulated Pedersen: m={m_int}, r={r_int}")
        try:
            g_pow_m = pow(g, m_int, p); h_pow_r = pow(h, r_int, p)
            cm = (g_pow_m * h_pow_r) % p
            logging.debug(f"  Simulated Pedersen commitment cm = {cm}")
            return str(cm)
        except Exception as e: logging.error(f"Error calculating simulated Pedersen: {e}"); raise

    @staticmethod
    def poseidon_commit_for_zkp(inputs):
        """Generates commitment using Poseidon hash via snarkjs_utils for ZKP purposes."""
        logging.debug(f"Creating Poseidon commitment for ZKP inputs: {inputs}")
        str_inputs = [str(i) for i in inputs]
        try: return poseidon_hash(str_inputs)
        except NameError: logging.error("poseidon_hash unavailable."); raise NotImplementedError("Poseidon unavailable")
        except Exception as e: logging.error(f"Error during poseidon_commit wrapper call: {e}"); raise

    @staticmethod
    def hash(data):
        """通用 SHA256 哈希函数 (返回十六进制字符串, 无 0x 前缀)"""
        if isinstance(data, str): data_bytes = data.encode('utf-8')
        elif isinstance(data, (dict, list)): data_bytes = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        elif isinstance(data, bytes): data_bytes = data
        elif isinstance(data, (int, float)): data_bytes = str(data).encode('utf-8')
        else: data_bytes = str(data).encode('utf-8')
        return hashlib.sha256(data_bytes).hexdigest()

    @staticmethod
    def generate_random_r(length=64):
         return ''.join(random.choices(string.hexdigits.lower(), k=length))

    @staticmethod
    def generate_rsa_key_pair():
        logging.debug("Generating new RSA key pair (2048 bits)..."); key = RSA.generate(2048)
        private_key = key.export_key(); public_key = key.publickey().export_key()
        vrf_private_key = private_key; vrf_public_key = public_key # Simulation
        logging.debug("RSA and simulated VRF keys generated."); return private_key, public_key, vrf_private_key, vrf_public_key

    @staticmethod
    def rsa_sign(message_bytes, private_key_pem):
        logging.debug(f"RSA Signing message (bytes len: {len(message_bytes)})...")
        try: key = RSA.import_key(private_key_pem); h = SHA256.new(message_bytes); signature = pkcs1_15.new(key).sign(h); b64_sig = base64.b64encode(signature).decode('utf-8'); logging.debug(f"RSA Signature (base64): {b64_sig[:10]}..."); return b64_sig
        except Exception as e: logging.error(f"RSA signing failed: {e}"); raise

    @staticmethod
    def rsa_verify(message_bytes, signature_b64, public_key_pem):
        logging.debug(f"RSA Verifying message (len: {len(message_bytes)}) against signature: {signature_b64[:10]}...")
        try: key = RSA.import_key(public_key_pem); h = SHA256.new(message_bytes); signature_bytes = base64.b64decode(signature_b64.encode('utf-8')); pkcs1_15.new(key).verify(h, signature_bytes); logging.debug("RSA Verification successful."); return True
        except (ValueError, TypeError, IndexError) as e: logging.warning(f"RSA Verification failed: {e}"); return False
        except Exception as e: logging.error(f"Unexpected RSA verification error: {e}"); return False

    # --- Simulated VRF (Renamed) ---
    @staticmethod
    def _simulate_vrf_prove(sk_bytes, input_bytes):
        logging.debug(f"Simulated VRF Prove: Input={input_bytes.hex()[:10]}...")
        pseudo_random_output = hashlib.sha256(sk_bytes + input_bytes).digest()
        proof = hashlib.sha512(sk_bytes + input_bytes + pseudo_random_output).digest()
        logging.debug(f"Simulated VRF Prove: Output={pseudo_random_output.hex()}, Proof={proof.hex()[:10]}...")
        return pseudo_random_output, proof

    @staticmethod
    def _simulate_vrf_verify(pk_bytes, input_bytes, output_bytes, proof_bytes):
        logging.debug(f"Simulated VRF Verify: Input={input_bytes.hex()[:10]}... -> Forcing True")
        return True # Force pass

    @staticmethod
    def simulate_generate_vrf(private_key_bytes, input_data):
        input_bytes = str(input_data).encode('utf-8')
        return CryptoUtils._simulate_vrf_prove(private_key_bytes, input_bytes)

    @staticmethod
    def simulate_verify_vrf(public_key_bytes, input_data, output_bytes, proof_bytes):
        input_bytes = str(input_data).encode('utf-8')
        return CryptoUtils._simulate_vrf_verify(public_key_bytes, input_bytes, output_bytes, proof_bytes)

    # --- HTLC Hash & Preimage (Keccak256) ---
    @staticmethod
    def generate_htlc_hash_and_preimage():
        preimage_oi_bytes = os.urandom(32)
        try: from web3 import Web3; hash_lock_bytes = Web3.keccak(preimage_oi_bytes)
        except ImportError: logging.error("Web3 not available for Keccak256!"); hash_lock_bytes = hashlib.sha256(preimage_oi_bytes).digest()
        h_i_hex = hash_lock_bytes.hex(); htlc_hash = "0x" + h_i_hex
        logging.debug(f"Generated HTLC Preimage(O_i)=<random bytes32>, Hash(H_i)={htlc_hash[:10]}... (Keccak256)")
        return htlc_hash, preimage_oi_bytes

    # --- Simplified VTS ---
    @staticmethod
    def generate_simplified_vts(layer_data_hash_hex, htlc_hash_hex, rsa_private_key_pem):
        layer_hash_clean = layer_data_hash_hex[2:] if layer_data_hash_hex.startswith('0x') else layer_data_hash_hex
        htlc_hash_clean = htlc_hash_hex[2:] if htlc_hash_hex.startswith('0x') else htlc_hash_hex
        message_to_sign_str = f"{layer_hash_clean}|{htlc_hash_clean}"
        message_to_sign_bytes = message_to_sign_str.encode('utf-8')
        logging.debug(f"Generating VTS signature for message: '{message_to_sign_str}'")
        base_signature_b64 = CryptoUtils.rsa_sign(message_to_sign_bytes, rsa_private_key_pem)
        vts_tuple = { "signature": base_signature_b64, "htlc_hash": htlc_hash_hex }
        return vts_tuple

    @staticmethod
    def verify_simplified_vts(layer_data, vts_tuple, rsa_public_key_pem):
        layer_data_hash_hex = CryptoUtils.hash(layer_data) # SHA256 hex, no 0x
        htlc_hash_hex = vts_tuple['htlc_hash']; signature_b64 = vts_tuple['signature']
        layer_hash_clean = layer_data_hash_hex
        htlc_hash_clean = htlc_hash_hex[2:] if htlc_hash_hex.startswith('0x') else htlc_hash_hex
        message_to_verify_str = f"{layer_hash_clean}|{htlc_hash_clean}"
        message_to_verify_bytes = message_to_verify_str.encode('utf-8')
        logging.debug(f"Verifying VTS signature for message: '{message_to_verify_str}'")
        return CryptoUtils.rsa_verify(message_to_verify_bytes, signature_b64, rsa_public_key_pem)

    # --- Simulated PRE (Renamed) ---
    @staticmethod
    def simulate_pre_encrypt(data, public_key_pem):
        logging.info("Simulating PRE: Encrypting data with target public key...")
        # ***** 调用移入类内部的 encrypt_data *****
        return CryptoUtils.encrypt_data(data, public_key_pem)

    @staticmethod
    def simulate_pre_decrypt(encrypted_chunks, private_key_pem):
        logging.info("Simulating PRE: Decrypting data with private key...")
        # ***** 调用移入类内部的 decrypt_data *****
        return CryptoUtils.decrypt_data(encrypted_chunks, private_key_pem)


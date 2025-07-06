# backend/src/snarkjs_utils.py
import json
import os
import subprocess
import tempfile
import hashlib
import logging
import platform # 导入 platform 用于路径检查

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)-7s] %(message)s')

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
ZK_SETUP_DIR = os.path.join(PROJECT_ROOT, 'zk_setup')
CIRCUITS_DIR = os.path.join(PROJECT_ROOT, 'circuits')

if not os.path.exists(ZK_SETUP_DIR):
    logging.warning(f"ZK Setup directory not found at {ZK_SETUP_DIR}.")

# ***** 开始修改: 定义 npx 的完整路径 *****
# 根据 'which npx' 的输出 /c/Program Files/nodejs/npx 确定 Windows 路径
# 注意：通常实际执行的是 npx.cmd
npx_executable_path = r'C:\Program Files\nodejs\npx.cmd'

# 检查路径是否存在
if not os.path.exists(npx_executable_path):
    logging.error(f"指定的 npx 路径无效: {npx_executable_path}")
    logging.error("请确认 Node.js 是否安装在 'C:\\Program Files\\nodejs' 目录下，")
    logging.error("并检查该目录下是否存在 'npx.cmd' 文件。如果路径不同，请修改上面 npx_executable_path 的值。")
    # 不直接退出，让后续调用失败时再退出
    # exit(1)
# ***** 修改结束 *****


def _run_command(command):
    logging.debug(f"Executing: {' '.join(command)}")
    try:
        # 检查命令的第一个元素是否存在
        cmd_to_check = command[0]
        if cmd_to_check == 'npx' and 'npx_executable_path' in globals() and os.path.exists(npx_executable_path):
             # 如果命令是 'npx' 且我们定义了有效路径，则替换
             command[0] = npx_executable_path
             logging.debug(f"Using full path for npx: {npx_executable_path}")
        elif not os.path.exists(cmd_to_check) and shutil.which(cmd_to_check) is None:
             # 如果命令本身不是完整路径，并且在 PATH 中也找不到
             logging.error(f"Error: Command '{command[0]}' not found via path check or 'which'.")
             raise FileNotFoundError(f"Command '{command[0]}' not found.")

        # 使用 Popen 执行
        process = subprocess.Popen(command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True,
                                   encoding='utf-8', errors='ignore',
                                   cwd=PROJECT_ROOT, # 在项目根目录执行
                                   shell=False) # 避免不必要的 shell 嵌套
        stdout, stderr = process.communicate()
        retcode = process.returncode

        if stdout: logging.debug(f"Command stdout:\n{stdout.strip()}")
        if stderr: logging.warning(f"Command stderr:\n{stderr.strip()}") # 记录 stderr

        if retcode != 0:
            raise subprocess.CalledProcessError(retcode, command, output=stdout, stderr=stderr)
        return stdout

    except FileNotFoundError as e:
         # 现在更可能是 npx_executable_path 配置错误，或者 snarkjs 没安装导致 npx 失败
         logging.error(f"Error running command '{' '.join(command)}': FileNotFoundError - {e}")
         logging.error(f"请检查 '{command[0]}' 是否存在且路径正确，以及 PATH 环境变量。")
         if command[0] == npx_executable_path and len(command)>1 and command[1] == 'snarkjs':
              logging.error("这通常意味着虽然找到了 npx.cmd，但 npx 无法找到或执行 snarkjs。请确认 snarkjs 已通过 'npm install -g snarkjs' 正确安装。")
         raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {' '.join(command)}")
        # 记录更详细的错误
        stdout_msg = e.stdout if e.stdout is not None else "[No stdout captured or Decode Error]"
        stderr_msg = e.stderr if e.stderr is not None else "[No stderr captured or Decode Error]"
        logging.error(f"Return code: {e.returncode}")
        logging.error("Stdout:\n" + stdout_msg)
        logging.error("Stderr:\n" + stderr_msg)
        raise
    except Exception as e:
        logging.error(f"Unexpected error running command {' '.join(command)}: {e}")
        raise


def _get_circuit_paths(circuit_name):
    setup_path = os.path.join(ZK_SETUP_DIR, circuit_name)
    wasm_path = os.path.join(setup_path, f'{circuit_name}_js', f'{circuit_name}.wasm')
    zkey_path = os.path.join(setup_path, 'circuit_final.zkey')
    vkey_path = os.path.join(setup_path, 'verification_key.json')

    if not os.path.exists(setup_path):
         raise FileNotFoundError(f"ZK setup directory not found: {setup_path}")
    if not os.path.exists(wasm_path):
         legacy_wasm_path = os.path.join(setup_path, 'circuit.wasm')
         if os.path.exists(legacy_wasm_path): wasm_path = legacy_wasm_path
         else:
             legacy_wasm_path_2 = os.path.join(setup_path, 'circuit_js', 'circuit.wasm')
             if os.path.exists(legacy_wasm_path_2): wasm_path = legacy_wasm_path_2
             else: raise FileNotFoundError(f"WASM file not found: {wasm_path}")
    if not os.path.exists(zkey_path):
         raise FileNotFoundError(f"Proving key not found: {zkey_path}")
    if not os.path.exists(vkey_path):
         raise FileNotFoundError(f"Verification key not found: {vkey_path}")

    return wasm_path, zkey_path, vkey_path

# --- Core snarkjs Interaction Functions ---

def generate_witness_and_proof(circuit_name, inputs):
    logging.info(f"Generating witness and proof for circuit: {circuit_name}")
    wasm_path, zkey_path, _ = _get_circuit_paths(circuit_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        input_json_path = os.path.join(tmpdir, 'input.json')
        witness_wtns_path = os.path.join(tmpdir, 'witness.wtns')
        proof_json_path = os.path.join(tmpdir, 'proof.json')
        public_json_path = os.path.join(tmpdir, 'public.json')

        try:
            with open(input_json_path, 'w', encoding='utf-8') as f:
                json.dump(inputs, f, indent=2)
            logging.debug(f"Wrote inputs for {circuit_name} to {input_json_path}")
        except Exception as e:
             logging.error(f"Failed to write input JSON for {circuit_name}: {e}")
             raise

        # 1. Generate Witness
        logging.info(f"--> Generating witness for {circuit_name}...")
        # ***** 修改: 使用 'npx' 字符串，_run_command 会处理路径 *****
        wit_cmd = ['npx', 'snarkjs', 'wtns', 'calculate', wasm_path, input_json_path, witness_wtns_path]
        _run_command(wit_cmd)
        logging.info(f"--> Witness generated: {witness_wtns_path}")

        # 2. Generate Proof (Groth16)
        logging.info(f"--> Generating proof for {circuit_name}...")
        # ***** 修改: 使用 'npx' 字符串 *****
        proof_cmd = ['npx', 'snarkjs', 'groth16', 'prove', zkey_path, witness_wtns_path, proof_json_path, public_json_path]
        _run_command(proof_cmd)
        logging.info(f"--> Proof generated: {proof_json_path}, Public signals: {public_json_path}")

        try:
            with open(proof_json_path, 'r', encoding='utf-8') as f:
                proof = json.load(f)
            with open(public_json_path, 'r', encoding='utf-8') as f:
                public_signals = json.load(f)
        except Exception as e:
             logging.error(f"Failed to read proof/public JSON files for {circuit_name}: {e}")
             raise

        logging.debug(f"Proof object: {json.dumps(proof)}")
        logging.debug(f"Public signals: {public_signals}")

        return proof, public_signals

def verify_proof(circuit_name, proof, public_signals):
    logging.info(f"Verifying proof off-chain for circuit: {circuit_name}")
    _, _, vkey_path = _get_circuit_paths(circuit_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        proof_json_path = os.path.join(tmpdir, 'proof.json')
        public_json_path = os.path.join(tmpdir, 'public.json')

        try:
            with open(proof_json_path, 'w', encoding='utf-8') as f:
                json.dump(proof, f)
            with open(public_json_path, 'w', encoding='utf-8') as f:
                json.dump(public_signals, f)
        except Exception as e:
            logging.error(f"Failed to write temporary proof/public JSON for verification: {e}")
            return False

        logging.info(f"--> Calling snarkjs verify for {circuit_name}...")
        # ***** 修改: 使用 'npx' 字符串 *****
        verify_cmd = ['npx', 'snarkjs', 'groth16', 'verify', vkey_path, public_json_path, proof_json_path]
        try:
            output = _run_command(verify_cmd)
            if "OK!" in output:
                logging.info(f"--> Proof verified successfully for {circuit_name}!")
                return True
            else:
                logging.warning(f"--> Proof verification failed for {circuit_name}.")
                logging.debug(f"Full snarkjs verify output:\n{output}")
                return False
        except subprocess.CalledProcessError:
             logging.error(f"--> Proof verification command failed for {circuit_name}.")
             return False
        except Exception as e:
             logging.error(f"--> An unexpected error during snarkjs verify: {e}")
             return False

# --- Utility Functions ---
# hash_data_for_circuit 和 poseidon_hash 保持不变 (除了 poseidon_hash 内部的 Popen 调用)

def hash_data_for_circuit(data):
    # ... (代码同上一个回复) ...
    if isinstance(data, str): data_bytes = data.encode('utf-8')
    elif isinstance(data, (dict, list)): data_bytes = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    elif isinstance(data, bytes): data_bytes = data
    elif isinstance(data, (int, float)): data_bytes = str(data).encode('utf-8')
    else: data_bytes = str(data).encode('utf-8')
    h = hashlib.sha256(data_bytes).digest()
    val = int.from_bytes(h, 'big')
    logging.debug(f"Hashed '{str(data)[:50]}...' to field element int string: {str(val)[:10]}...")
    return str(val)

def poseidon_hash(inputs):
    # ... (代码同上一个回复，使用 Popen 或 run 均可) ...
    logging.debug(f"Calculating Poseidon hash for inputs: {inputs}")
    str_inputs = [str(i) for i in inputs]
    js_lib = "poseidon-encryption"
    js_func = "poseidon"
    js_script_content = f"""
const {{ {js_func} }} = require("{js_lib}");
const inputs = {json.dumps(str_inputs)};
try {{ const bigIntInputs = inputs.map(inp => BigInt(inp)); const result = {js_func}(bigIntInputs); console.log(result.toString()); }}
catch (e) {{ console.error(`Error in Node.js Poseidon script (${{e.message}}):`, e.stack); process.exit(1); }}
"""
    temp_js_filename = f"temp_poseidon_hash_{os.getpid()}.js"
    js_file_path = os.path.join(PROJECT_ROOT, temp_js_filename)
    node_modules_path = os.path.join(PROJECT_ROOT, 'node_modules', js_lib)
    if not os.path.isdir(node_modules_path):
         npm_command = f"npm install {js_lib}"
         logging.error(f"Node.js library '{js_lib}' not found at {node_modules_path}.")
         logging.error(f"Please run '{npm_command}' in the project root ('{PROJECT_ROOT}').")
         raise ModuleNotFoundError(f"Node.js library '{js_lib}' not found. Run '{npm_command}'.")
    try:
        with open(js_file_path, 'w', encoding='utf-8') as js_file: js_file.write(js_script_content)
        logging.debug(f"Temporary Poseidon script created at: {js_file_path}")
        node_command = ['node', temp_js_filename]
        result = subprocess.run( node_command, capture_output=True, text=True, check=True,
            cwd=PROJECT_ROOT, encoding='utf-8', errors='ignore', env=os.environ.copy() )
        output_hash = result.stdout.strip()
        if result.stderr or not output_hash:
             stderr_msg = result.stderr if result.stderr else "[No stderr]"
             logging.error(f"Poseidon hash script failed or returned empty. Stderr:\n{stderr_msg}")
             raise ValueError("Poseidon hash script returned empty or error.")
        logging.debug(f"Poseidon hash result: {output_hash}")
        return str(output_hash)
    # ... (异常处理保持不变) ...
    except FileNotFoundError: logging.error("Error: 'node' command not found."); raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Node.js script for Poseidon hash failed."); stderr_msg = e.stderr if e.stderr is not None else "[No stderr]"; logging.error(f"Node stderr:\n{stderr_msg}")
        if "Cannot find module" in stderr_msg: logging.error(f"Node.js still cannot find module '{js_lib}'.")
        raise RuntimeError("Poseidon hash calculation via Node.js failed.") from e
    except Exception as e: logging.error(f"Unexpected error calculating Poseidon hash: {e}"); raise RuntimeError("Failed to calculate Poseidon hash") from e
    finally: # 确保删除临时文件
        if os.path.exists(js_file_path):
            try: os.remove(js_file_path); logging.debug(f"Removed temporary Poseidon script: {js_file_path}")
            except OSError as e: logging.warning(f"Could not remove temporary script {js_file_path}: {e}")
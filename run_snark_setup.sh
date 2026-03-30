#!/bin/bash

# 遇到错误立即退出
set -e

# 允许通过环境变量覆盖工具路径（如在 Windows Git Bash 中可能需要指向 .cmd 文件）
# 默认直接使用系统路径中的命令
SNARKJS=${SNARKJS_BIN:-snarkjs}
CIRCOM=${CIRCOM_BIN:-circom}

# macOS 和 Linux环境下 sed -i 参数要求的差异
SED_I=("sed" "-i")
if [[ "$OSTYPE" == "darwin"* ]]; then
   
    SED_I=("sed" "-i" "")
fi


# 定义需要处理的电路名称
CIRCUITS=("age_id" "layer1" "layer2" "layer3" "credential_check") 

# Power of Tau 文件路径配置
PTAU_FILE="powersOfTau/pot18_final.ptau" 
PTAU_DIR=$(dirname "$PTAU_FILE")

# 检查或下载 Power of Tau 文件 
echo "**** 1. Generating/Downloading Power of Tau file ****"
mkdir -p "$PTAU_DIR"
if [ ! -f "$PTAU_FILE" ]; then
    echo "Downloading Power of Tau file (BN254 Phase 1, 2^18 constraints)..."
    PTAU_URL="https://storage.googleapis.com/trustedsetup-a86f4/phase1/powersOfTau28_hez_final_18.ptau"
    echo "Downloading from: $PTAU_URL"
    curl -L "$PTAU_URL" -o "$PTAU_FILE" --progress-bar
    
    # 简单的文件完整性校验
    file_size_mb=$(du -m "$PTAU_FILE" | cut -f1)
    if [ "$file_size_mb" -lt 90 ]; then
        echo "[ERROR] Downloaded ptau file size ($file_size_mb MB) is too small."
        rm "$PTAU_FILE"
        exit 1
    fi
    echo "Download complete."
else
    echo "Power of Tau file already exists."
fi

# 循环处理各个电路：编译、设置、导出验证器 
for circuit_name in "${CIRCUITS[@]}"; do
    echo ""
    echo "**** Processing circuit: $circuit_name ****"
    
    CIRCUIT_DIR="circuits/$circuit_name"
    SETUP_DIR="zk_setup/$circuit_name"
    
    # 创建必要的目录
    mkdir -p "$SETUP_DIR"
    mkdir -p contracts/Verifiers

    # 编译电路 
    echo "Compiling $circuit_name.circom..."
    if [ ! -f "$CIRCUIT_DIR/circuit.circom" ]; then 
        echo "[ERROR] Circuit file not found: $CIRCUIT_DIR/circuit.circom"
        exit 1
    fi

    # 使用兼容性变量 $CIRCOM，并保留 -l node_modules 参数
    $CIRCOM "$CIRCUIT_DIR/circuit.circom" --r1cs --wasm --sym --output "$SETUP_DIR" -l node_modules

    echo "Compilation complete."
    $SNARKJS info -r "$SETUP_DIR/circuit.r1cs"

    # 运行 Phase 2 Setup (Groth16)
    echo "Performing Phase 2 setup for $circuit_name..."
    $SNARKJS groth16 setup "$SETUP_DIR/circuit.r1cs" "$PTAU_FILE" "$SETUP_DIR/circuit_0000.zkey"
    
  
    random_entropy=$(head -c 1024 /dev/urandom | base64 | head -c 128 || echo "fallback_entropy_$(date +%s)")
    
    echo "Using generated entropy for contribution..."
    $SNARKJS zkey contribute "$SETUP_DIR/circuit_0000.zkey" "$SETUP_DIR/circuit_final.zkey" --name="1st Contribution" -v -e="$random_entropy"
    echo "Phase 2 setup complete."

    # 导出验证密钥与 Solidity 验证合约
    echo "Exporting Verifier contract for $circuit_name..."
    VERIFIER_SOL="contracts/Verifiers/Verifier_${circuit_name}.sol"
    
    $SNARKJS zkey export verificationkey "$SETUP_DIR/circuit_final.zkey" "$SETUP_DIR/verification_key.json"
    $SNARKJS zkey export solidityverifier "$SETUP_DIR/circuit_final.zkey" "$VERIFIER_SOL"

    # 使用兼容性 SED 指令修改合约内部名称，避免重名冲突
    "${SED_I[@]}" "s/contract Verifier/contract Verifier_${circuit_name}/g" "$VERIFIER_SOL"
    
    if [ -f "${VERIFIER_SOL}.bak" ]; then rm "${VERIFIER_SOL}.bak"; fi
    
    echo "Verifier contract exported to $VERIFIER_SOL and renamed."

done

echo ""
echo "**** SNARK Setup Complete ****"

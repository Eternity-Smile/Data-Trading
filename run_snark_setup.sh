#!/bin/bash

# Exit on error
set -e

# Circuit names
CIRCUITS=("age_id" "layer1" "layer2" "layer3" "credential_check") # 确保包含所有电路

# Power of Tau file
PTAU_FILE="powersOfTau/pot18_final.ptau" # 确认 ptau 文件名和路径
PTAU_DIR=$(dirname "$PTAU_FILE")

# --- 1. Power of Tau ---
echo "**** 1. Generating/Downloading Power of Tau file ****"
mkdir -p "$PTAU_DIR"
if [ ! -f "$PTAU_FILE" ]; then
    echo "Downloading Power of Tau file (BN254 Phase 1, 2^18 constraints)..."
    PTAU_URL="https://storage.googleapis.com/trustedsetup-a86f4/phase1/powersOfTau28_hez_final_18.ptau"
    echo "Downloading from: $PTAU_URL"
    curl -L "$PTAU_URL" -o "$PTAU_FILE" --progress-bar
    file_size_mb=$(du -m "$PTAU_FILE" | cut -f1)
    if [ "$file_size_mb" -lt 90 ]; then
        echo "[ERROR] Downloaded ptau file size ($file_size_mb MB) is too small."
        rm "$PTAU_FILE"; exit 1
    fi
    echo "Download complete."
else
    echo "Power of Tau file already exists."
fi

# --- 2. Compile Circuits, Setup, Export Verifier ---
for circuit_name in "${CIRCUITS[@]}"; do
    echo ""
    echo "**** Processing circuit: $circuit_name ****"
    CIRCUIT_DIR="circuits/$circuit_name"
    SETUP_DIR="zk_setup/$circuit_name"
    mkdir -p "$SETUP_DIR"
    mkdir -p contracts/Verifiers

    # --- 2a. Compile Circuit ---
    echo "Compiling $circuit_name.circom..."
    if [ ! -f "$CIRCUIT_DIR/circuit.circom" ]; then echo "[ERROR] Circuit file not found: $CIRCUIT_DIR/circuit.circom"; exit 1; fi

    # ***** 修改: 添加 -l node_modules 参数 *****
    circom "$CIRCUIT_DIR/circuit.circom" --r1cs --wasm --sym --output "$SETUP_DIR" -l node_modules
    # ***** 修改结束 *****

    echo "Compilation complete."
    snarkjs info -r "$SETUP_DIR/circuit.r1cs"

    # --- 2b. Phase 2 Setup (Groth16) ---
    echo "Performing Phase 2 setup for $circuit_name..."
    snarkjs groth16 setup "$SETUP_DIR/circuit.r1cs" "$PTAU_FILE" "$SETUP_DIR/circuit_0000.zkey"
    random_entropy=$(head -c 1024 /dev/urandom | base64 | head -c 128 || echo "fallback_entropy_$(date +%s)") # Add fallback for systems without /dev/urandom
    echo "Using generated entropy for contribution..."
    snarkjs zkey contribute "$SETUP_DIR/circuit_0000.zkey" "$SETUP_DIR/circuit_final.zkey" --name="1st Contribution" -v -e="$random_entropy"
    echo "Phase 2 setup complete."

    # --- 2c. Export Verifier Contract ---
    echo "Exporting Verifier contract for $circuit_name..."
    VERIFIER_SOL="contracts/Verifiers/Verifier_${circuit_name}.sol"
    snarkjs zkey export verificationkey "$SETUP_DIR/circuit_final.zkey" "$SETUP_DIR/verification_key.json"
    snarkjs zkey export solidityverifier "$SETUP_DIR/circuit_final.zkey" "$VERIFIER_SOL"

    # Fix contract name inside the exported file
    sed -i.bak "s/contract Verifier/contract Verifier_${circuit_name}/g" "$VERIFIER_SOL"
    if [ -f "${VERIFIER_SOL}.bak" ]; then rm "${VERIFIER_SOL}.bak"; fi
    echo "Verifier contract exported to $VERIFIER_SOL and renamed."

done

echo ""
echo "**** SNARK Setup Complete ****"

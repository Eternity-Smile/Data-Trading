# Data Trading on a Zero-Trust Basis: A Protocol Implementation

This repository contains the prototype implementation for the research paper, "Data Trading on a Zero-Trust Basis: A Protocol for Layered, Verifiable Atomic Swaps." The project demonstrates a novel protocol that enables secure, fair, and private data trading by integrating zero-knowledge proofs (ZKPs), hash-time locked contracts (HTLCs), and a layered transaction structure on the Ethereum blockchain.

## Project Structure

The repository is organized into several key directories, each with a specific purpose:

-   **/contracts**: Contains the Solidity smart contracts, including the main trading contract and the ZKP verifier contract (`Verifier_layer3.sol`).
-   **/circuits**: Contains the `circom` source code for the zero-knowledge circuits used in the protocol.
-   **/zk_setup**: Includes scripts and will hold the generated artifacts from the ZKP trusted setup, such as the `.r1cs`, `.wasm`, and final `.zkey` files. The `run_snark_setup.sh` script automates this process.
-   **/src**: Contains the core Python logic for off-chain operations, user interactions, and communication with the blockchain via web3.py (`web3_utils.py`).
-   **/build-contracts**: Truffle's output directory for compiled contract artifacts (`.json` files).
-   **/migrations**: Truffle scripts for deploying the smart contracts to the blockchain.

---

## Prerequisites

Before you begin, ensure you have the following software installed on your system:

-   **Node.js**: v14.x or later (which includes npm)
-   **Python**: v3.8 or later
-   **Truffle Suite**: `npm install -g truffle`
-   **Ganache**: A local Ethereum blockchain. We recommend the UI version for easy inspection of transactions, available at [trufflesuite.com/ganache/](https://trufflesuite.com/ganache/).

---

## Installation and Setup

Please follow these steps in order to set up the project environment.

### 1. Clone the Repository

```bash
git clone [https://github.com/yourusername/secure_data_trading.git](https://github.com/yourusername/secure_data_trading.git)
cd secure_data_trading

2. Install Node.js Dependencies
This step installs project-specific dependencies defined in package.json. Note that this will download a large number of packages into the node_modules directory, which is why it is not checked into version control.

npm install

3. Run the ZKP Trusted Setup
Our protocol relies on zk-SNARKs generated with circom and snarkjs. We have provided a script to automate the entire process of compiling the circuit, performing the trusted setup (Powers of Tau), and generating the verifier smart contract.

Important: This is a required, one-time setup process.

# Execute the setup script from the root directory
bash run_snark_setup.sh

4. Set Up the Python Environment
It is highly recommended to use a Python virtual environment to manage dependencies.

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install the required Python packages
pip install web3 pycryptodome numpy matplotlib pandas pytest flask

Execution Workflow
To run the full experimental simulation, please follow these steps in order.

1. Start Your Local Blockchain
Launch your Ganache UI instance or run the Ganache CLI in a separate terminal. Ensure it is running on the default RPC server address (e.g., http://127.0.0.1:8545).

2. Compile and Deploy Smart Contracts
Open a new terminal in the project's root directory.

# Compile the smart contracts
truffle compile

# Deploy the contracts to your local Ganache network
truffle migrate


3. Run the Experiments
Ensure your Python virtual environment from Step 4 is activated.

Main Experiment
The main.py script runs the end-to-end data trading protocol simulation. You can control the size of the dataset used with command-line arguments.

# Run with the default setting (all datasets)
python main.py

# Run with a specific dataset size
python main.py --dataset small
python main.py --dataset medium
python main.py --dataset large

# Skip the initial setup verification (if already done)
python main.py --skip-setup

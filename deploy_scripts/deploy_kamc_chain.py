# deploy_kamc_chain.py
import json
import os
from web3 import Web3

# --- Configuration ---
KAMC_CHAIN_RPC_URL = "http://127.0.0.1:8547"  # Default Hardhat node 3 for KAMC-Chain
# Assumes this script is in 'deployment_scripts' and 'kamc-chain-project' is a sibling directory
HARDHAT_PROJECT_ROOT = "../kamc-chain-project/"
ENTITY_REGISTRY_CONTRACT_NAME = "EntityRegistry"
KAMC_CONTROL_CONTRACT_NAME = "KAMCControl"
# Replace with a private key from your Hardhat node (e.g., the first account on the third node)
# Ensure this account has ETH on the KAMC-Chain for gas
DEPLOYER_PRIVATE_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" # Example private key for Hardhat node 3, account 0

# --- Helper Functions ---
def load_contract_artifact(contract_name):
    # Path assumes contract .sol file is directly in 'contracts' folder of the Hardhat project
    artifact_path = os.path.join(
        HARDHAT_PROJECT_ROOT,
        "artifacts",
        "contracts",
        f"{contract_name}.sol",
        f"{contract_name}.json"
    )
    if not os.path.exists(artifact_path):
        raise FileNotFoundError(
            f"Artifact not found at {artifact_path}. "
            f"Ensure \'{contract_name}.sol\' is in \'{os.path.join(HARDHAT_PROJECT_ROOT, 'contracts')}\' "
            f"and you have compiled your Hardhat project in \'{HARDHAT_PROJECT_ROOT}\' (e.g., npx hardhat compile)."
        )
    with open(artifact_path, 'r') as f:
        artifact = json.load(f)
    return artifact['abi'], artifact['bytecode']

def deploy_contract(w3, abi, bytecode, private_key, *constructor_args):
    account = w3.eth.account.from_key(private_key)
    w3.eth.default_account = account.address

    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    
    constructor_txn = Contract.constructor(*constructor_args).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gasPrice': w3.eth.gas_price
    })
    try:
        gas_estimate = w3.eth.estimate_gas(constructor_txn)
        constructor_txn['gas'] = gas_estimate
    except Exception as e:
        print(f"Gas estimation failed: {e}. Using a default gas limit of 4,000,000.")
        constructor_txn['gas'] = 4000000 # KAMC contracts might be larger

    signed_txn = w3.eth.account.sign_transaction(constructor_txn, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"Deploying contract... TX Hash: {tx_hash.hex()}")
    
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    if tx_receipt.status == 0:
        raise Exception(f"Transaction failed: {tx_receipt}")
        
    print(f"Contract deployed successfully! Address: {tx_receipt.contractAddress}")
    return tx_receipt.contractAddress

# --- Main Deployment Logic ---
def main():
    print(f"--- Deploying to KAMC-Chain ({KAMC_CHAIN_RPC_URL}) ---")
    w3_kamc = Web3(Web3.HTTPProvider(KAMC_CHAIN_RPC_URL))

    if not w3_kamc.is_connected():
        print(f"Failed to connect to KAMC-Chain RPC at {KAMC_CHAIN_RPC_URL}")
        return

    print(f"Connected to KAMC-Chain. Chain ID: {w3_kamc.eth.chain_id}")
    deployer_account = w3_kamc.eth.account.from_key(DEPLOYER_PRIVATE_KEY)
    print(f"Deployer address: {deployer_account.address}")
    print(f"Deployer balance: {w3_kamc.from_wei(w3_kamc.eth.get_balance(deployer_account.address), 'ether')} ETH")

    # 1. Deploy EntityRegistry
    print(f"\nDeploying {ENTITY_REGISTRY_CONTRACT_NAME}...")
    er_abi, er_bytecode = load_contract_artifact(ENTITY_REGISTRY_CONTRACT_NAME)
    entity_registry_address = deploy_contract(w3_kamc, er_abi, er_bytecode, DEPLOYER_PRIVATE_KEY)

    # 2. Deploy KAMCControl
    # KAMCControl constructor takes EntityRegistry address as an argument.
    print(f"\nDeploying {KAMC_CONTROL_CONTRACT_NAME}...")
    kc_abi, kc_bytecode = load_contract_artifact(KAMC_CONTROL_CONTRACT_NAME)
    kamc_control_address = deploy_contract(w3_kamc, kc_abi, kc_bytecode, DEPLOYER_PRIVATE_KEY)

    print("\n--- KAMC-Chain Deployment Complete ---")
    print(f"Successfully deployed contracts to KAMC-Chain ({KAMC_CHAIN_RPC_URL}):")
    print(f"  {ENTITY_REGISTRY_CONTRACT_NAME}: {entity_registry_address}")
    print(f"  {KAMC_CONTROL_CONTRACT_NAME}: {kamc_control_address}")
    print("\nACTION REQUIRED: Copy the above addresses to your 'deployed_addresses.json' file or directly into the main demo script configuration.")

if __name__ == "__main__":
    # Dummy artifact creation for basic local script testing
    contract_names_for_dummy = [ENTITY_REGISTRY_CONTRACT_NAME, KAMC_CONTROL_CONTRACT_NAME]
    for contract_name in contract_names_for_dummy:
        dummy_artifact_dir = os.path.join(HARDHAT_PROJECT_ROOT, "artifacts", "contracts", f"{contract_name}.sol")
        dummy_artifact_json = os.path.join(dummy_artifact_dir, f"{contract_name}.json")
        if not os.path.exists(dummy_artifact_json):
            print(f"Warning: Dummy artifact creation for {contract_name}. This is for script testing only.")
            os.makedirs(dummy_artifact_dir, exist_ok=True)
            # Simplified dummy ABI/Bytecode for testing script logic
            dummy_content = {"abi": [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"}], "bytecode": "0x00"}
            if contract_name == KAMC_CONTROL_CONTRACT_NAME: # It has a constructor argument
                dummy_content = {"abi": [{"inputs":[{"internalType":"address","name":"_entityRegistryAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"}], "bytecode": "0x00"}
            with open(dummy_artifact_json, 'w') as f:
                json.dump(dummy_content, f)
    main()


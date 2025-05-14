"""
Event-Driven Cross-Chain Education Credential Demo

This script demonstrates a cross-chain workflow for issuing and verifying
educational credentials, using real on-chain interactions and event listening.
It interacts with three separate Hardhat nodes simulating different blockchains:
- UNI-Chain: For University Registry
- EMP-Chain: For Employer Verification Requests and Student Consent
- KAMC-Chain: For Entity Registry and KAMC Control (ABE/TSS parameters)

Assumes ABI files (e.g., UniversityRegistry.abi) are in the same directory as this script.
Assumes crypto_simulations modules are in a subdirectory named 'crypto_simulations'.
"""
import json
import os
import time
import hashlib
import re # Added for robust ABI parsing
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware # For PoA chains like Hardhat default

# Import crypto simulation modules
from crypto_simulations.abe_simulation import ABESimulation
from crypto_simulations.mpc_simulation import MPCSimulation
from crypto_simulations.tss_simulation import TSSSimulation
from crypto_simulations.zkp_simulation import ZKPSimulation

# --- Configuration (User Provided or Default) ---
# It's crucial that these private keys correspond to accounts with ETH on their respective chains.
# The addresses are derived from these private keys.
CONFIG = {
    "UNI_CHAIN": {
        "RPC_URL": "http://127.0.0.1:8545",
        "UniversityRegistry": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        # This account is the owner/deployer of UniRegistry and will issue credentials.
        "ACCOUNT_ADDRESS": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", # Hardhat Account #0
        "PRIVATE_KEY": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    },
    "EMP_CHAIN": {
        "RPC_URL": "http://127.0.0.1:8546",
        "VerificationRequester": "0x8464135c8F25Da09e49BC8782676a84730C318bC",
        "StudentConsentRegistry": "0x71C95911E9a5D330f4D621842EC243EE1343292e",
        # This account is the deployer/admin on EMP-Chain, can also act as relayer.
        "ACCOUNT_ADDRESS": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", # Hardhat Account #1
        "PRIVATE_KEY": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    },
    "KAMC_CHAIN": {
        "RPC_URL": "http://127.0.0.1:8547",
        "EntityRegistry": "0x663F3ad617193148711d28f5334eE4Ed07016602",
        "KAMCControl": "0x2E983A1Ba5e8b38AAAeC4B440B9dDcFBf72E15d1",
        # This account is the KAMC Admin, registers University, updates KAMCControl.
        "ACCOUNT_ADDRESS": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", # Hardhat Account #2
        "PRIVATE_KEY": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
        # Check: Who is owner of this contract 
    }
}

# Specific accounts for roles on KAMC chain if different from KAMC_CHAIN admin
# These PKs must correspond to accounts with ETH on KAMC-Chain (port 8547)
STUDENT_KAMC_PK = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" # Hardhat Account #4 PK
EMPLOYER_KAMC_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Hardhat Account #0 PK

# Specific account for student on EMP-Chain (for consent)
# This PK must correspond to an account with ETH on EMP-Chain (port 8546)
STUDENT_EMP_PK = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" # Hardhat Account #4 PK

# --- Off-Chain Storage Simulation ---
OFF_CHAIN_ENCRYPTED_CREDENTIALS = {}  # {degree_hash_hex: encrypted_credential_data_json_str}
OFF_CHAIN_ENCRYPTED_ABE_KEYS_STUDENT = {} # {student_kamc_id: abe_secret_key_sim}
OFF_CHAIN_ENCRYPTED_ABE_KEYS_EMPLOYER = {} # {request_id: abe_secret_key_sim}

# --- Load ABI files ---
def load_abi(contract_name):
    abi_file_path = f"{contract_name}.abi"
    if not os.path.exists(abi_file_path):
        raise FileNotFoundError(f"ABI file not found: {abi_file_path}. Please place it in the same directory as the script.")
    
    with open(abi_file_path, 'r') as f:
        content = f.read().strip()

    try:
        abi_list = json.loads(content)
        if isinstance(abi_list, list):
            return abi_list
    except json.JSONDecodeError:
        pass

    try:
        parsed_obj = json.loads(content)
        if isinstance(parsed_obj, dict) and "abi" in parsed_obj and isinstance(parsed_obj["abi"], list):
            return parsed_obj["abi"]
    except json.JSONDecodeError:
        pass

    match = re.match(r'"abi":\s*(.*)', content, re.DOTALL)
    if match:
        json_array_str = match.group(1).strip()
        try:
            abi_list = json.loads(json_array_str)
            if isinstance(abi_list, list):
                return abi_list
        except json.JSONDecodeError as e:
            raise ValueError(f"""Failed to parse ABI array for {contract_name} from '"abi": [...]' format after extraction. Extracted: {repr(json_array_str[:100])}... Original Error: {e}""")
    raise ValueError(f"Could not parse ABI for {contract_name}. Unrecognized format. Content: {content[:200]}...")

# --- Web3 Setup ---
w3_uni = Web3(Web3.HTTPProvider(CONFIG["UNI_CHAIN"]["RPC_URL"]))
w3_emp = Web3(Web3.HTTPProvider(CONFIG["EMP_CHAIN"]["RPC_URL"]))
w3_kamc = Web3(Web3.HTTPProvider(CONFIG["KAMC_CHAIN"]["RPC_URL"]))

for w3_instance in [w3_uni, w3_emp, w3_kamc]:
    if not w3_instance.is_connected():
        print(f"{w3_instance.provider.endpoint_uri} is not connected. Please ensure Hardhat node is running.")
        # exit() # Optionally exit if a chain is not connected
    w3_instance.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

if not all(w3.is_connected() for w3 in [w3_uni, w3_emp, w3_kamc]):
    print("One or more chains are not connected. Please fix chain connectivity issues before running the demo.")
    exit()
else:
    print("All chains connected successfully.")

# --- Contract Instances ---
contracts = {
    "uni": {},
    "emp": {},
    "kamc": {}
}

try:
    contracts["uni"]["UniversityRegistry"] = w3_uni.eth.contract(
        address=CONFIG["UNI_CHAIN"]["UniversityRegistry"],
        abi=load_abi("UniversityRegistry")
    )
    contracts["emp"]["VerificationRequester"] = w3_emp.eth.contract(
        address=CONFIG["EMP_CHAIN"]["VerificationRequester"],
        abi=load_abi("VerificationRequester")
    )
    contracts["emp"]["StudentConsentRegistry"] = w3_emp.eth.contract(
        address=CONFIG["EMP_CHAIN"]["StudentConsentRegistry"],
        abi=load_abi("StudentConsentRegistry")
    )
    contracts["kamc"]["EntityRegistry"] = w3_kamc.eth.contract(
        address=CONFIG["KAMC_CHAIN"]["EntityRegistry"],
        abi=load_abi("EntityRegistry")
    )
    contracts["kamc"]["KAMCControl"] = w3_kamc.eth.contract(
        address=CONFIG["KAMC_CHAIN"]["KAMCControl"],
        abi=load_abi("KAMCControl")
    )
except FileNotFoundError as e:
    print(f"Error loading ABI: {e}")
    exit()
except ValueError as e:
    print(f"Error parsing ABI: {e}")
    exit()
except Exception as e:
    print(f"An error occurred during contract setup: {e}")
    exit()

print("Web3 instances and contract objects initialized.")

# --- Crypto Simulation Instances ---
abe_sim = ABESimulation()
mpc_sim = MPCSimulation(num_parties=3)
tss_sim = TSSSimulation(num_participants=3, threshold=2)
zkp_sim = ZKPSimulation()

print("Cryptographic simulations initialized.")

# --- Helper Functions for Transactions ---
def send_transaction(w3, contract_function, account_private_key):
    account_address = w3.eth.account.from_key(account_private_key).address
    nonce = w3.eth.get_transaction_count(account_address)
    gas_price = w3.eth.gas_price
    
    txn_params = {
        'from': account_address,
        'nonce': nonce,
        'gasPrice': gas_price
    }
    
    try:
        estimated_gas = contract_function.estimate_gas(txn_params)
        txn_params['gas'] = estimated_gas
    except Exception as e:
        print(f"Gas estimation failed for {contract_function.fn_name} by {account_address}: {e}. Using default gas limit 3,000,000")
        txn_params['gas'] = 3000000

    transaction = contract_function.build_transaction(txn_params)
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=account_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"Transaction sent ({contract_function.fn_name} by {account_address}): {tx_hash.hex()}")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    if tx_receipt.status == 0:
        print(f"Transaction FAILED ({contract_function.fn_name} by {account_address}): {tx_receipt.transactionHash.hex()}")
        raise Exception(f"Transaction failed: {tx_receipt.transactionHash.hex()}")
    print(f"Transaction successful ({contract_function.fn_name} by {account_address}): {tx_receipt.transactionHash.hex()}")
    return tx_receipt

def wait_for_event(event_filter, timeout=60, poll_interval=2):
    start_time = time.time()
    while time.time() < start_time + timeout:
        try:
            new_events = event_filter.get_new_entries()
            if new_events:
                return new_events
        except Exception as e:
            print(f"Error fetching events: {e}. Retrying...")
        time.sleep(poll_interval)
    print(f"Timeout waiting for event")
    return []

# --- Main Demo Logic ---
def main_demo():
    print("\n--- Starting Event-Driven Cross-Chain Education Credential Demo ---")

    kamc_admin_pk = CONFIG["KAMC_CHAIN"]["PRIVATE_KEY"]
    kamc_admin_address = Web3.to_checksum_address(w3_kamc.eth.account.from_key(kamc_admin_pk).address)
    print(f"DEBUG: KAMC Admin Address for University registration (from CONFIG): {kamc_admin_address}")

    student_kamc_address = Web3.to_checksum_address(w3_kamc.eth.account.from_key(STUDENT_KAMC_PK).address)
    employer_kamc_address = Web3.to_checksum_address(w3_kamc.eth.account.from_key(EMPLOYER_KAMC_PK).address)
    student_emp_chain_address = Web3.to_checksum_address(w3_emp.eth.account.from_key(STUDENT_EMP_PK).address)

    print("\n--- 1. Entity Registration on KAMC-Chain ---")
    entity_registry_contract = contracts["kamc"]["EntityRegistry"]
    kamc_control_contract = contracts["kamc"]["KAMCControl"]

    # Register University (Stanford)
    stanford_kamc_id = ""
    try:
        print(f"DEBUG: Attempting to call getEntityIdByPrimaryAddress for University Admin: {kamc_admin_address}...")
        retrieved_id = entity_registry_contract.functions.getEntityIdByPrimaryAddress(kamc_admin_address).call()
        print(f"DEBUG: Raw ID returned from getEntityIdByPrimaryAddress for University: '{retrieved_id}' (Type: {type(retrieved_id)}, Length: {len(retrieved_id)})")
        if retrieved_id and isinstance(retrieved_id, str) and retrieved_id.strip():
            stanford_kamc_id = retrieved_id.strip()
            print(f"DEBUG: University (Admin: {kamc_admin_address}) appears ALREADY REGISTERED with KAMC ID: '{stanford_kamc_id}'")
        else:
            print(f"DEBUG: getEntityIdByPrimaryAddress for University returned an empty, whitespace, or non-string ID: '{retrieved_id}'. Proceeding to register.")
    except Exception as e_retrieve:
        print(f"DEBUG: Exception during getEntityIdByPrimaryAddress for University Admin {kamc_admin_address}: {e_retrieve}")
        print(f"DEBUG: Assuming University not registered, proceeding to registration attempt.")

    if not stanford_kamc_id:
        print(f"DEBUG: Attempting to register University (Stanford) by KAMC Admin ({kamc_admin_address}) as ID was not found or was empty/invalid.")
        try:
            tx_receipt_uni_reg = send_transaction(
                w3_kamc,
                entity_registry_contract.functions.registeredUniversities(
                    "Stanford University", 
                    CONFIG["UNI_CHAIN"]["UniversityRegistry"], 
                    "Top Tier University"
                ),
                kamc_admin_pk 
            )
            print(f"DEBUG: University Registration transaction sent. Receipt: {tx_receipt_uni_reg.transactionHash.hex()}")
            parsed_event_id = None
            for log_entry in tx_receipt_uni_reg.get('logs', []):
                try:
                    event_data = entity_registry_contract.events.EntityRegistered().process_log(log_entry)
                    print(f"DEBUG: Processed event log for UniReg: {event_data}")
                    if event_data['args']['name'] == "Stanford University" and Web3.to_checksum_address(event_data['args']['primaryAddress']) == kamc_admin_address:
                        parsed_event_id = event_data['args']['entityId_on_KAMC_Chain']
                        print(f"DEBUG: Stanford KAMC ID from event (newly registered): '{parsed_event_id}'")
                        break
                except Exception as e_event_parse:
                    print(f"DEBUG: Error processing UniReg event log or not the EntityRegistered event: {e_event_parse}")
            
            if parsed_event_id and isinstance(parsed_event_id, str) and parsed_event_id.strip():
                stanford_kamc_id = parsed_event_id.strip()
            else:
                print(f"DEBUG: Failed to get KAMC ID from Uni registration event. Will try to retrieve it again.")
                try:
                    retrieved_id_after_reg = entity_registry_contract.functions.getEntityIdByPrimaryAddress(kamc_admin_address).call()
                    print(f"DEBUG: Raw ID returned from getEntityIdByPrimaryAddress for University (after reg attempt): '{retrieved_id_after_reg}' (Type: {type(retrieved_id_after_reg)}, Length: {len(retrieved_id_after_reg)})")
                    if retrieved_id_after_reg and isinstance(retrieved_id_after_reg, str) and retrieved_id_after_reg.strip():
                        stanford_kamc_id = retrieved_id_after_reg.strip()
                        print(f"DEBUG: Successfully retrieved KAMC ID for University after re-attempt: '{stanford_kamc_id}'")
                    else:
                        print(f"DEBUG: Still could not retrieve a valid KAMC ID for University after registration re-attempt. Returned: '{retrieved_id_after_reg}'")
                except Exception as e_retrieve_after_reg:
                    print(f"DEBUG: Exception retrieving KAMC ID for University after registration re-attempt: {e_retrieve_after_reg}")
        except Exception as e_register:
            print(f"DEBUG: Exception during actual registration transaction for University: {e_register}")

    if not stanford_kamc_id or not (isinstance(stanford_kamc_id, str) and stanford_kamc_id.strip()):
        print(f"FINAL CHECK - UNIVERSITY: Could not retrieve or register a valid Stanford KAMC ID. Current ID value: '{stanford_kamc_id}'. Exiting.")
        return
    else:
        print(f"FINAL CHECK - UNIVERSITY: Stanford KAMC ID successfully set to: '{stanford_kamc_id}'. Proceeding...")

    # Register Student (Alice)
    alice_kamc_id = ""
    try:
        print(f"DEBUG: Attempting to call getEntityIdByPrimaryAddress for Student: {student_kamc_address}...")
        retrieved_id_student = entity_registry_contract.functions.getEntityIdByPrimaryAddress(student_kamc_address).call()
        print(f"DEBUG: Raw ID returned from getEntityIdByPrimaryAddress for Student: '{retrieved_id_student}' (Type: {type(retrieved_id_student)}, Length: {len(retrieved_id_student)})")
        if retrieved_id_student and isinstance(retrieved_id_student, str) and retrieved_id_student.strip():
            alice_kamc_id = retrieved_id_student.strip()
            print(f"DEBUG: Student (Address: {student_kamc_address}) appears ALREADY REGISTERED with KAMC ID: '{alice_kamc_id}'")
        else:
            print(f"DEBUG: getEntityIdByPrimaryAddress for Student returned an empty, whitespace, or non-string ID: '{retrieved_id_student}'. Proceeding to register.")
    except Exception as e_retrieve_student:
        print(f"DEBUG: Exception during getEntityIdByPrimaryAddress for Student {student_kamc_address}: {e_retrieve_student}")
        print(f"DEBUG: Assuming Student not registered, proceeding to registration attempt.")
    
    if not alice_kamc_id:
        print(f"DEBUG: Attempting to register Student (Alice) by Student Address ({student_kamc_address}) as ID was not found or was empty/invalid.")
        try:
            tx_receipt_stu_reg = send_transaction(
                w3_kamc,
                entity_registry_contract.functions.registerStudent("Alice Wonderland", "CS Student"),
                STUDENT_KAMC_PK 
            )
            print(f"DEBUG: Student Registration transaction sent. Receipt: {tx_receipt_stu_reg.transactionHash.hex()}")
            parsed_event_id_student = None
            for log_entry in tx_receipt_stu_reg.get('logs', []):
                try:
                    event_data_student = entity_registry_contract.events.EntityRegistered().process_log(log_entry)
                    print(f"DEBUG: Processed event log for StuReg: {event_data_student}")
                    if event_data_student['args']['name'] == "Alice Wonderland" and Web3.to_checksum_address(event_data_student['args']['primaryAddress_on_KAMC_Chain']) == student_kamc_address:
                        parsed_event_id_student = event_data_student['args']['entityId_on_KAMC_Chain']
                        print(f"DEBUG: Alice KAMC ID from event (newly registered): '{parsed_event_id_student}'")
                        break
                except Exception as e_event_parse_student:
                    print(f"DEBUG: Error processing StuReg event log or not the EntityRegistered event for Alice: {e_event_parse_student}")
            
            if parsed_event_id_student and isinstance(parsed_event_id_student, str) and parsed_event_id_student.strip():
                alice_kamc_id = parsed_event_id_student.strip()
            else:
                print(f"DEBUG: Failed to get KAMC ID from Student registration event. Will try to retrieve it again.")
                try:
                    retrieved_id_student_after_reg = entity_registry_contract.functions.getEntityIdByPrimaryAddress(student_kamc_address).call()
                    print(f"DEBUG: Raw ID returned from getEntityIdByPrimaryAddress for Student (after reg attempt): '{retrieved_id_student_after_reg}' (Type: {type(retrieved_id_student_after_reg)}, Length: {len(retrieved_id_student_after_reg)})")
                    if retrieved_id_student_after_reg and isinstance(retrieved_id_student_after_reg, str) and retrieved_id_student_after_reg.strip():
                        alice_kamc_id = retrieved_id_student_after_reg.strip()
                        print(f"DEBUG: Successfully retrieved KAMC ID for Student after re-attempt: '{alice_kamc_id}'")
                    else:
                        print(f"DEBUG: Still could not retrieve a valid KAMC ID for Student after registration re-attempt. Returned: '{retrieved_id_student_after_reg}'")
                except Exception as e_retrieve_student_after_reg:
                    print(f"DEBUG: Exception retrieving KAMC ID for Student after registration re-attempt: {e_retrieve_student_after_reg}")
        except Exception as e_register_student:
            print(f"DEBUG: Exception during actual registration transaction for Student: {e_register_student}")

    if not alice_kamc_id or not (isinstance(alice_kamc_id, str) and alice_kamc_id.strip()):
        print(f"FINAL CHECK - STUDENT: Could not retrieve or register a valid Alice KAMC ID. Current ID value: '{alice_kamc_id}'. Exiting.")
        return
    else:
        print(f"FINAL CHECK - STUDENT: Alice KAMC ID successfully set to: '{alice_kamc_id}'. Proceeding...")

    # Register Employer (Google)
    google_kamc_id = ""
    try:
        print(f"DEBUG: Attempting to call getEntityIdByPrimaryAddress for Employer: {employer_kamc_address}...")
        retrieved_id_employer = entity_registry_contract.functions.getEntityIdByPrimaryAddress(employer_kamc_address).call()
        print(f"DEBUG: Raw ID returned from getEntityIdByPrimaryAddress for Employer: '{retrieved_id_employer}' (Type: {type(retrieved_id_employer)}, Length: {len(retrieved_id_employer)})")
        if retrieved_id_employer and isinstance(retrieved_id_employer, str) and retrieved_id_employer.strip():
            google_kamc_id = retrieved_id_employer.strip()
            print(f"DEBUG: Employer (Address: {employer_kamc_address}) appears ALREADY REGISTERED with KAMC ID: '{google_kamc_id}'")
        else:
            print(f"DEBUG: getEntityIdByPrimaryAddress for Employer returned an empty, whitespace, or non-string ID: '{retrieved_id_employer}'. Proceeding to register.")
    except Exception as e_retrieve_employer:
        print(f"DEBUG: Exception during getEntityIdByPrimaryAddress for Employer {employer_kamc_address}: {e_retrieve_employer}")
        print(f"DEBUG: Assuming Employer not registered, proceeding to registration attempt.")

    if not google_kamc_id:
        print(f"DEBUG: Attempting to register Employer (Google) by Employer Address ({employer_kamc_address}) as ID was not found or was empty/invalid.")
        try:
            tx_receipt_emp_reg = send_transaction(
                w3_kamc,
                entity_registry_contract.functions.registerEmployer(
                    "Google LLC", 
                    CONFIG["EMP_CHAIN"]["VerificationRequester"], 
                    "Tech Company"
                ),
                EMPLOYER_KAMC_PK 
            )
            print(f"DEBUG: Employer Registration transaction sent. Receipt: {tx_receipt_emp_reg.transactionHash.hex()}")
            parsed_event_id_employer = None
            for log_entry in tx_receipt_emp_reg.get('logs', []):
                try:
                    event_data_employer = entity_registry_contract.events.EntityRegistered().process_log(log_entry)
                    print(f"DEBUG: Processed event log for EmpReg: {event_data_employer}")
                    if event_data_employer['args']['name'] == "Google LLC" and Web3.to_checksum_address(event_data_employer['args']['primaryAddress_on_KAMC_Chain']) == employer_kamc_address:
                        parsed_event_id_employer = event_data_employer['args']['entityId_on_KAMC_Chain']
                        print(f"DEBUG: Google KAMC ID from event (newly registered): '{parsed_event_id_employer}'")
                        break
                except Exception as e_event_parse_employer:
                    print(f"DEBUG: Error processing EmpReg event log or not the EntityRegistered event for Google: {e_event_parse_employer}")
            
            if parsed_event_id_employer and isinstance(parsed_event_id_employer, str) and parsed_event_id_employer.strip():
                google_kamc_id = parsed_event_id_employer.strip()
            else:
                print(f"DEBUG: Failed to get KAMC ID from Employer registration event. Will try to retrieve it again.")
                try:
                    retrieved_id_employer_after_reg = entity_registry_contract.functions.getEntityIdByPrimaryAddress(employer_kamc_address).call()
                    print(f"DEBUG: Raw ID returned from getEntityIdByPrimaryAddress for Employer (after reg attempt): '{retrieved_id_employer_after_reg}' (Type: {type(retrieved_id_employer_after_reg)}, Length: {len(retrieved_id_employer_after_reg)})")
                    if retrieved_id_employer_after_reg and isinstance(retrieved_id_employer_after_reg, str) and retrieved_id_employer_after_reg.strip():
                        google_kamc_id = retrieved_id_employer_after_reg.strip()
                        print(f"DEBUG: Successfully retrieved KAMC ID for Employer after re-attempt: '{google_kamc_id}'")
                    else:
                        print(f"DEBUG: Still could not retrieve a valid KAMC ID for Employer after registration re-attempt. Returned: '{retrieved_id_employer_after_reg}'")
                except Exception as e_retrieve_employer_after_reg:
                    print(f"DEBUG: Exception retrieving KAMC ID for Employer after registration re-attempt: {e_retrieve_employer_after_reg}")
        except Exception as e_register_employer:
            print(f"DEBUG: Exception during actual registration transaction for Employer: {e_register_employer}")

    if not google_kamc_id or not (isinstance(google_kamc_id, str) and google_kamc_id.strip()):
        print(f"FINAL CHECK - EMPLOYER: Could not retrieve or register a valid Google KAMC ID. Current ID value: '{google_kamc_id}'. Exiting.")
        return
    else:
        print(f"FINAL CHECK - EMPLOYER: Google KAMC ID successfully set to: '{google_kamc_id}'. Proceeding...")
        
    print("Setting KAMC Control parameters (TSS PubKey, ABE PubParams)...")
    try:
        try:
            actual_owner = kamc_control_contract.functions.owner().call()
            expected_owner = CONFIG['KAMC_CHAIN']['ACCOUNT_ADDRESS']
            print(f"DEBUG: Expected KAMCControl owner (from CONFIG): {expected_owner}")
            print(f"DEBUG: Actual KAMCControl owner on KAMC-Chain: {actual_owner}")
            if Web3.to_checksum_address(actual_owner) != Web3.to_checksum_address(expected_owner):
                print("WARNING: KAMCControl owner mismatch! The contract on chain might have a different owner than configured.")
        except Exception as e_owner_check:
            print(f"DEBUG: Error checking KAMCControl owner: {e_owner_check}")

        send_transaction(
            w3_kamc,
            kamc_control_contract.functions.updateTSSPublicKey(tss_sim.public_key),
            kamc_admin_pk 
        )
        send_transaction(
            w3_kamc,
            kamc_control_contract.functions.updateABEPublicParams(abe_sim.public_parameters),
            kamc_admin_pk 
        )
        print("KAMC Control parameters updated.")
    except Exception as e:
        print(f"Error updating KAMC Control parameters: {e}. This might be okay if already set and contract prevents re-setting.")

    # --- 2. Credential Issuance Flow ---
    print("\n--- 2. Credential Issuance Flow ---")
    university_registry_contract = contracts["uni"]["UniversityRegistry"]
    uni_issuer_pk = CONFIG["UNI_CHAIN"]["PRIVATE_KEY"]
    uni_issuer_address_on_uni_chain = Web3.to_checksum_address(w3_uni.eth.account.from_key(uni_issuer_pk).address)

    try:
        is_uni_registered_on_uni_chain = university_registry_contract.functions.registeredUniversities(uni_issuer_address_on_uni_chain).call()
        if is_uni_registered_on_uni_chain:
            print(f"University {uni_issuer_address_on_uni_chain} already registered on UniRegistry.")
        else:
            print(f"Registering University {uni_issuer_address_on_uni_chain} on UniRegistry...")
            send_transaction(
                w3_uni,
                university_registry_contract.functions.registeredUniversities(stanford_kamc_id, "Stanford University"),
                uni_issuer_pk
            )
            print(f"University {uni_issuer_address_on_uni_chain} registered on UniRegistry.")
    except Exception as e:
        print(f"Error during University registration on UniRegistry: {e}")
        return

    degree_data = {
        "studentName": "Alice Wonderland",
        "degree": "B.S. Computer Science",
        "major": "Artificial Intelligence",
        "graduationYear": 2024,
        "issuingUniversityKAMCID": stanford_kamc_id,
        "studentKAMCID": alice_kamc_id
    }
    degree_data_json = json.dumps(degree_data)
    degree_hash_bytes = hashlib.sha256(degree_data_json.encode()).digest()
    degree_hash_hex = degree_hash_bytes.hex()

    abe_policy = f"student_id:{alice_kamc_id},degree_topic:B.S. Computer Science" 
    print(f"[ABE SIM] Encrypting data: {degree_data_json[:50]}... under policy: {abe_policy}")
    encrypted_degree_data = abe_sim.encrypt(degree_data_json, abe_policy)
    OFF_CHAIN_ENCRYPTED_CREDENTIALS[degree_hash_hex] = encrypted_degree_data
    print(f"Alice's degree hash (hex): {degree_hash_hex}")
    print(f"Encrypted degree data for {degree_hash_hex} stored off-chain.")

    print(f"Issuing credential for Alice ({alice_kamc_id}) by {uni_issuer_address_on_uni_chain}...")
    credential_issued_event_filter = university_registry_contract.events.CredentialIssued.create_filter(from_block='latest')
    
    send_transaction(
        w3_uni,
        university_registry_contract.functions.issueCredential(
            alice_kamc_id, 
            degree_hash_bytes, 
            f"ipfs://placeholder_for_encrypted_data_pointer/{degree_hash_hex}" # Off-chain pointer
        ),
        uni_issuer_pk
    )

    print("Waiting for CredentialIssued event...")
    credential_issued_events = wait_for_event(credential_issued_event_filter)
    if not credential_issued_events:
        print("No CredentialIssued event received. Exiting verification flow.")
        return
    
    issued_event_args = credential_issued_events[0]['args']
    print(f"CredentialIssued event received: Student KAMC ID: {issued_event_args['studentId_on_KAMC_Chain']}, Degree Hash: {issued_event_args['degreeHash'].hex()}")

    # --- 3. Verification Request Flow ---
    print("\n--- 3. Verification Request Flow ---")
    verification_requester_contract = contracts["emp"]["VerificationRequester"]
    emp_chain_admin_pk = CONFIG["EMP_CHAIN"]["PRIVATE_KEY"]

    verification_request_id_on_emp_chain = int(time.time() * 1000) # Unique request ID
    attributes_for_abe_key = {"student_id": alice_kamc_id, "degree_topic": "B.S. Computer Science"}
    attributes_for_abe_key_json = json.dumps(attributes_for_abe_key)

    print(f"Employer (Google, KAMC ID: {google_kamc_id}) requesting verification for Alice's degree (hash: {degree_hash_hex})...")
    verification_requested_event_filter = verification_requester_contract.events.VerificationRequested.create_filter(from_block='latest')
    
    send_transaction(
        w3_emp,
        verification_requester_contract.functions.requestVerification(
            verification_request_id_on_emp_chain,
            google_kamc_id, # Employer's KAMC ID
            alice_kamc_id,  # Student's KAMC ID
            degree_hash_bytes,
            attributes_for_abe_key_json # Attributes for ABE key generation
        ),
        emp_chain_admin_pk # For demo, EMP chain admin initiates, could be employer's own account on EMP chain
    )

    print("Waiting for VerificationRequested event...")
    verification_requested_events = wait_for_event(verification_requested_event_filter)
    if not verification_requested_events:
        print("No VerificationRequested event received. Exiting.")
        return

    requested_event_args = verification_requested_events[0]['args']
    print(f"VerificationRequested event received: Request ID {requested_event_args['requestId_on_EMP_Chain']}, Requester KAMC ID {requested_event_args['requesterId_on_KAMC_Chain']}")

    # --- 4. KAMC ABE Key Generation Request (Simulated Relayer/KAMC Action) ---
    print("\n--- 4. KAMC ABE Key Generation Request ---")
    # KAMC (or a relayer) sees VerificationRequested, now requests ABE key from KAMCControl
    abe_key_req_id_on_kamc = 0
    try:
        print(f"KAMC requesting ABE key generation for EMP request ID: {requested_event_args['requestId_on_EMP_Chain']} by {requested_event_args['requesterId_on_KAMC_Chain']} with attributes: {attributes_for_abe_key_json}")
        abe_key_requested_event_filter = kamc_control_contract.events.ABEKeyGenerationRequested.create_filter(from_block='latest')
        tx_receipt_abe_req = send_transaction(
            w3_kamc,
            kamc_control_contract.functions.requestABEKeyGeneration(
                requested_event_args['requesterId_on_KAMC_Chain'], # This is Google's KAMC ID
                attributes_for_abe_key_json
            ),
            kamc_admin_pk # KAMC Admin initiates this
        )
        for log_entry in tx_receipt_abe_req.get('logs', []):
            try:
                event_data = kamc_control_contract.events.ABEKeyGenerationRequested().process_log(log_entry)
                abe_key_req_id_on_kamc = event_data['args']['requestId']
                print(f"ABEKeyGenerationRequested event on KAMC: Request ID {abe_key_req_id_on_kamc}")
                break
            except Exception:
                pass
        if abe_key_req_id_on_kamc == 0:
             raise Exception("Failed to get ABEKeyGenerationRequested event or ID from KAMC.")

    except Exception as e:
        print(f"Error during KAMC ABE Key Generation Request: {e}")
        return

    # --- 5. KAMC Generates and Confirms ABE Key (Simulated KAMC Action) ---
    print("\n--- 5. KAMC Generates and Confirms ABE Key (Off-chain + On-chain confirmation) ---")
    # KAMC members use MPC/TSS to generate ABE key for the policy
    print(f"[MPC/TSS SIM] KAMC members collaboratively generating ABE key for attributes: {attributes_for_abe_key_json}...")
    # In a real scenario, this involves MPC for master secret key shares and ABE key generation algorithm
    abe_user_secret_key_sim = abe_sim.generate_user_key(attributes_for_abe_key)
    print(f"[ABE SIM] Generated ABE User Secret Key (simulated): {str(abe_user_secret_key_sim)[:50]}...")
    
    # Encrypt this key or store pointer to it (simulation: store directly for employer)
    OFF_CHAIN_ENCRYPTED_ABE_KEYS_EMPLOYER[abe_key_req_id_on_kamc] = abe_user_secret_key_sim 
    encrypted_abe_key_pointer = f"offchain_kamc_storage://abe_key_for_req_{abe_key_req_id_on_kamc}"
    print(f"ABE User Secret Key stored off-chain (simulated) at: {encrypted_abe_key_pointer}")

    try:
        print(f"KAMC confirming ABE key generation for KAMC Request ID: {abe_key_req_id_on_kamc}")
        abe_key_ready_event_filter = kamc_control_contract.events.ABEKeyReady.create_filter(from_block='latest')
        send_transaction(
            w3_kamc,
            kamc_control_contract.functions.confirmABEKeyGenerated(abe_key_req_id_on_kamc, encrypted_abe_key_pointer),
            kamc_admin_pk # KAMC Admin confirms
        )
        print("Waiting for ABEKeyReady event...")
        abe_key_ready_events = wait_for_event(abe_key_ready_event_filter)
        if not abe_key_ready_events:
            print("No ABEKeyReady event received. Exiting.")
            return
        print(f"ABEKeyReady event received for KAMC Request ID: {abe_key_ready_events[0]['args']['requestId']}")
    except Exception as e:
        print(f"Error during KAMC ABE Key Confirmation: {e}")
        return

    # --- 6. Student Consent Flow ---
    print("\n--- 6. Student Consent Flow ---")
    student_consent_registry_contract = contracts["emp"]["StudentConsentRegistry"]
    
    # Student (Alice) generates ZKP of credential ownership
    # For ZKP, student needs the original degree data to prove they know it.
    # In a real system, student would have their copy or be able to reconstruct it.
    print(f"[ZKP SIM] Alice generating ZKP for degree hash: {degree_hash_hex}")
    zkp_proof_sim = zkp_sim.generate_proof(degree_data_json, {"action": "consent_to_verify"})
    print(f"[ZKP SIM] ZKP generated (simulated): {zkp_proof_sim[:50]}...")

    print(f"Alice (KAMC ID: {alice_kamc_id}, EMP Address: {student_emp_chain_address}) granting consent for verification request ID: {requested_event_args['requestId_on_EMP_Chain']}")
    consent_granted_event_filter = student_consent_registry_contract.events.ConsentGrantedWithZKP.create_filter(from_block='latest')
    
    send_transaction(
        w3_emp,
        student_consent_registry_contract.functions.grantConsentWithZKP(
            requested_event_args['requestId_on_EMP_Chain'],
            zkp_proof_sim, # Simulated ZKP
            zkp_sim.verification_key # Simulated ZKP verification key
        ),
        STUDENT_EMP_PK # Student's account on EMP-Chain
    )

    print("Waiting for ConsentGrantedWithZKP event...")
    consent_granted_events = wait_for_event(consent_granted_event_filter)
    if not consent_granted_events:
        print("No ConsentGrantedWithZKP event received. Exiting.")
        return
    print(f"ConsentGrantedWithZKP event received for EMP Request ID: {consent_granted_events[0]['args']['requestId_on_EMP_Chain']}")

    # --- 7. Verification Completion (Simulated Relayer/Employer Action) ---
    print("\n--- 7. Verification Completion ---")
    # Employer/Relayer sees ABEKeyReady and ConsentGrantedWithZKP
    # Employer retrieves the ABE key (simulated)
    retrieved_abe_key_for_employer = OFF_CHAIN_ENCRYPTED_ABE_KEYS_EMPLOYER.get(abe_key_req_id_on_kamc)
    if not retrieved_abe_key_for_employer:
        print(f"ERROR: Could not retrieve ABE key for employer for KAMC request ID {abe_key_req_id_on_kamc}")
        return
    print(f"Employer retrieved ABE User Secret Key (simulated): {str(retrieved_abe_key_for_employer)[:50]}...")

    # Employer retrieves encrypted credential data (simulated)
    retrieved_encrypted_credential = OFF_CHAIN_ENCRYPTED_CREDENTIALS.get(degree_hash_hex)
    if not retrieved_encrypted_credential:
        print(f"ERROR: Could not retrieve encrypted credential for hash {degree_hash_hex}")
        return
    print(f"Employer retrieved encrypted credential data (simulated): {retrieved_encrypted_credential[:50]}...")

    # Employer decrypts credential data using ABE key
    print(f"[ABE SIM] Employer attempting to decrypt credential with retrieved key...")
    try:
        decrypted_degree_data_json = abe_sim.decrypt(retrieved_encrypted_credential, retrieved_abe_key_for_employer)
        decrypted_degree_data = json.loads(decrypted_degree_data_json)
        print(f"[ABE SIM] Successfully decrypted degree data: {decrypted_degree_data}")
        
        # Basic validation
        if decrypted_degree_data.get("studentKAMCID") == alice_kamc_id and hashlib.sha256(decrypted_degree_data_json.encode()).hexdigest() == degree_hash_hex:
            print("SUCCESS: Credential data decrypted and hash matches. Verification successful!")
            
            # Employer confirms verification on EMP-Chain
            print(f"Employer confirming verification for EMP Request ID: {requested_event_args['requestId_on_EMP_Chain']}")
            verification_completed_event_filter = verification_requester_contract.events.VerificationCompleted.create_filter(from_block='latest')
            send_transaction(
                w3_emp,
                verification_requester_contract.functions.confirmVerification(
                    requested_event_args['requestId_on_EMP_Chain'],
                    True, # Verification successful
                    "Verified successfully via ABE decryption and ZKP consent."
                ),
                emp_chain_admin_pk # Could be employer's account on EMP chain
            )
            print("Waiting for VerificationCompleted event...")
            verification_completed_events = wait_for_event(verification_completed_event_filter)
            if verification_completed_events:
                print(f"VerificationCompleted event received for EMP Request ID: {verification_completed_events[0]['args']['requestId_on_EMP_Chain']}, Status: {verification_completed_events[0]['args']['success']}")
            else:
                print("Did not receive VerificationCompleted event.")

        else:
            print("ERROR: Decrypted data does not match expected student or hash. Verification FAILED.")
            # Optionally confirm failure on-chain

    except Exception as e_decrypt:
        print(f"[ABE SIM] ERROR: Failed to decrypt credential data: {e_decrypt}. Verification FAILED.")
        # Optionally confirm failure on-chain

    print("\n--- Demo Complete ---")

if __name__ == "__main__":
    try:
        main_demo()
    except Exception as e:
        print(f"An error occurred during the demo: {e}")
        import traceback
        traceback.print_exc()
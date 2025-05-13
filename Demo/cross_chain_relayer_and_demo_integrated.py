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
        "EntityRegistry": "0xC469e7aE4aD962c30c7111dc580B4adbc7E914DD",
        "KAMCControl": "0x43ca3D2C94be00692D207C6A1e60D8B325c6f12f",
        # This account is the KAMC Admin, registers University, updates KAMCControl.
        "ACCOUNT_ADDRESS": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", # Hardhat Account #2
        "PRIVATE_KEY": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
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
        content = f.read()

    # Attempt 1: Content is a valid JSON array `[...]`
    try:
        abi_list = json.loads(content)
        if isinstance(abi_list, list):
            # print(f"Successfully parsed ABI for {contract_name} as direct JSON array.")
            return abi_list
    except json.JSONDecodeError:
        pass  # Not a direct JSON array, try other formats

    # Attempt 2: Content is a valid JSON object `{"abi": [...]}`
    try:
        parsed_obj = json.loads(content)
        if isinstance(parsed_obj, dict) and "abi" in parsed_obj and isinstance(parsed_obj["abi"], list):
            # print(f"Successfully parsed ABI for {contract_name} from JSON object {{'abi': [...]}}.")
            return parsed_obj["abi"]
    except json.JSONDecodeError:
        pass # Not a direct JSON object or not the right structure, try other formats

    # Attempt 3: Content is a string starting with '"abi":' followed by a JSON array string.
    # Example: '"abi": [ ... ]' (This is not valid JSON by itself but seen in user's repo)
    match = re.match(r'"abi":\s*(.*)', content, re.DOTALL)
    if match:
        json_array_str = match.group(1).strip() # This should be '[...]' or similar
        try:
            abi_list = json.loads(json_array_str)
            if isinstance(abi_list, list):
                # print(f"Successfully parsed ABI for {contract_name} from '"abi": [...]' format.")
                return abi_list
        except json.JSONDecodeError as e:
            # This specific error is for when json_array_str itself is not valid JSON
            raise ValueError(f"""Failed to parse ABI array for {contract_name} from '"abi": [...]' format after extraction. Extracted: {repr(json_array_str[:100])}... Original Error: {e}""")
    # If we reach here, all attempts (1, 2, and 3 if match was true) have failed to return an ABI.
    raise ValueError(f"Could not parse ABI for {contract_name}. Unrecognized format. Content: {content[:200]}...")

# --- Web3 Setup ---
w3_uni = Web3(Web3.HTTPProvider(CONFIG["UNI_CHAIN"]["RPC_URL"]))
w3_emp = Web3(Web3.HTTPProvider(CONFIG["EMP_CHAIN"]["RPC_URL"]))
w3_kamc = Web3(Web3.HTTPProvider(CONFIG["KAMC_CHAIN"]["RPC_URL"]))

# Inject PoA middleware for Hardhat local nodes
for w3_instance in [w3_uni, w3_emp, w3_kamc]:
    w3_instance.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

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
mpc_sim = MPCSimulation(num_parties=3) # KAMC members
tss_sim = TSSSimulation(num_participants=3, threshold=2) # KAMC members for TSS
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
        try:
            tx_data = w3.eth.get_transaction(tx_hash)
            # Try to decode revert reason if available (works with Hardhat)
            # This is a simplified approach; a more robust one would inspect the actual revert data if present.
            # result = w3.eth.call(tx_data, tx_data['blockNumber'] -1 if tx_data['blockNumber'] else 'latest')
            # print(f"Revert reason (from eth_call): {result.decode('utf-8', errors='ignore') if isinstance(result, bytes) else result}")
        except Exception as e_revert:
            print(f"Could not fetch detailed revert reason: {e_revert}")
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
            print(f"Error fetching events for {event_filter.event_name if hasattr(event_filter, 'event_name') else 'unknown event'}: {e}. Retrying...")
        time.sleep(poll_interval)
    print(f"Timeout waiting for event: {event_filter.event_name if hasattr(event_filter, 'event_name') else 'unknown event'}")
    return []

# --- Main Demo Logic ---
def main_demo():
    print("\n--- Starting Event-Driven Cross-Chain Education Credential Demo ---")

    kamc_admin_pk = CONFIG["KAMC_CHAIN"]["PRIVATE_KEY"]
    kamc_admin_address = Web3.to_checksum_address(w3_kamc.eth.account.from_key(kamc_admin_pk).address)

    student_kamc_address = Web3.to_checksum_address(w3_kamc.eth.account.from_key(STUDENT_KAMC_PK).address)
    employer_kamc_address = Web3.to_checksum_address(w3_kamc.eth.account.from_key(EMPLOYER_KAMC_PK).address)
    
    student_emp_chain_address = Web3.to_checksum_address(w3_emp.eth.account.from_key(STUDENT_EMP_PK).address)

    # --- 1. Entity Registration on KAMC-Chain (Idempotent) ---
    print("\n--- 1. Entity Registration on KAMC-Chain ---")
    entity_registry_contract = contracts["kamc"]["EntityRegistry"]
    kamc_control_contract = contracts["kamc"]["KAMCControl"]

    # Register University (Stanford)
    stanford_kamc_id = ""
    try:
        stanford_kamc_id = entity_registry_contract.functions.getEntityIdByPrimaryAddress(kamc_admin_address).call()
        print(f"University (Admin: {kamc_admin_address}) already registered with KAMC ID: {stanford_kamc_id}")
    except Exception as e:
        # A more specific check for "entity not found" or revert reason is better if available from contract
        print(f"Attempting to register University (Stanford) by KAMC Admin ({kamc_admin_address}) as it might not be registered or call failed: {str(e)[:100]}")
        tx_receipt_uni_reg = send_transaction(
            w3_kamc,
            entity_registry_contract.functions.registerUniversity(
                "Stanford University", 
                CONFIG["UNI_CHAIN"]["UniversityRegistry"], 
                "Top Tier University"
            ),
            kamc_admin_pk 
        )
        for log_entry in tx_receipt_uni_reg.get('logs', []):
            try:
                event_data = entity_registry_contract.events.EntityRegistered().process_log(log_entry)
                if event_data['args']['name'] == "Stanford University" and Web3.to_checksum_address(event_data['args']['primaryAddress']) == kamc_admin_address:
                    stanford_kamc_id = event_data['args']['entityId_on_KAMC_Chain']
                    print(f"Stanford KAMC ID (newly registered): {stanford_kamc_id}")
                    break
            except Exception:
                pass # Not the event we are looking for or error in processing
    if not stanford_kamc_id:
        print("Could not retrieve or register Stanford KAMC ID. Exiting.")
        return

    # Register Student (Alice)
    alice_kamc_id = ""
    try:
        alice_kamc_id = entity_registry_contract.functions.getEntityIdByPrimaryAddress(student_kamc_address).call()
        print(f"Student (Address: {student_kamc_address}) already registered with KAMC ID: {alice_kamc_id}")
    except Exception as e:
        print(f"Attempting to register Student (Alice) by Student Address ({student_kamc_address}) as it might not be registered or call failed: {str(e)[:100]}")
        tx_receipt_stu_reg = send_transaction(
            w3_kamc,
            entity_registry_contract.functions.registerStudent("Alice Wonderland", "CS Student"),
            STUDENT_KAMC_PK 
        )
        for log_entry in tx_receipt_stu_reg.get('logs', []):
            try:
                event_data = entity_registry_contract.events.EntityRegistered().process_log(log_entry)
                if event_data['args']['name'] == "Alice Wonderland" and Web3.to_checksum_address(event_data['args']['primaryAddress']) == student_kamc_address:
                    alice_kamc_id = event_data['args']['entityId_on_KAMC_Chain']
                    print(f"Alice KAMC ID (newly registered): {alice_kamc_id}")
                    break
            except Exception:
                pass
    if not alice_kamc_id:
        print("Could not retrieve or register Alice KAMC ID. Exiting.")
        return

    # Register Employer (Google)
    google_kamc_id = ""
    try:
        google_kamc_id = entity_registry_contract.functions.getEntityIdByPrimaryAddress(employer_kamc_address).call()
        print(f"Employer (Address: {employer_kamc_address}) already registered with KAMC ID: {google_kamc_id}")
    except Exception as e:
        print(f"Attempting to register Employer (Google) by Employer Address ({employer_kamc_address}) as it might not be registered or call failed: {str(e)[:100]}")
        tx_receipt_emp_reg = send_transaction(
            w3_kamc,
            entity_registry_contract.functions.registerEmployer(
                "Google LLC", 
                CONFIG["EMP_CHAIN"]["VerificationRequester"], 
                "Tech Company"
            ),
            EMPLOYER_KAMC_PK 
        )
        for log_entry in tx_receipt_emp_reg.get('logs', []):
            try:
                event_data = entity_registry_contract.events.EntityRegistered().process_log(log_entry)
                if event_data['args']['name'] == "Google LLC" and Web3.to_checksum_address(event_data['args']['primaryAddress']) == employer_kamc_address:
                    google_kamc_id = event_data['args']['entityId_on_KAMC_Chain']
                    print(f"Google KAMC ID (newly registered): {google_kamc_id}")
                    break
            except Exception:
                pass
    if not google_kamc_id:
        print("Could not retrieve or register Google KAMC ID. Exiting.")
        return
        
    print("Setting KAMC Control parameters (TSS PubKey, ABE PubParams)...")
    try:
        send_transaction(
            w3_kamc,
            kamc_control_contract.functions.updateTSSPublicKey(tss_sim.public_key),
            kamc_admin_pk 
        )
        send_transaction(
            w3_kamc,
            kamc_control_contract.functions.updateABEPublicParams(json.dumps(abe_sim.public_parameters).encode()),
            kamc_admin_pk 
        )
        print("KAMC Control parameters updated.")
    except Exception as e:
        print(f"Error updating KAMC Control parameters: {e}. This might be okay if already set and contract prevents re-setting.")

    # --- 2. Credential Issuance Flow ---
    print("\n--- 2. Credential Issuance Flow ---")
    university_registry_contract = contracts["uni"]["UniversityRegistry"]
    uni_issuer_address_on_uni_chain = Web3.to_checksum_address(CONFIG["UNI_CHAIN"]["ACCOUNT_ADDRESS"])
    uni_issuer_pk_on_uni_chain = CONFIG["UNI_CHAIN"]["PRIVATE_KEY"]

    try:
        is_uni_registered_on_registry = university_registry_contract.functions.registeredUniversities(uni_issuer_address_on_uni_chain).call()
        if not is_uni_registered_on_registry:
            print(f"University {uni_issuer_address_on_uni_chain} not registered on UniRegistry. Registering...")
            send_transaction(
                w3_uni,
                university_registry_contract.functions.registerUniversity(uni_issuer_address_on_uni_chain),
                uni_issuer_pk_on_uni_chain 
            )
            print(f"University {uni_issuer_address_on_uni_chain} registered on UniRegistry.")
        else:
            print(f"University {uni_issuer_address_on_uni_chain} already registered on UniRegistry.")
    except Exception as e:
        print(f"Error during university self-registration on UniRegistry: {e}")
        return

    alice_degree_details = {
        "studentName": "Alice Wonderland",
        "degree": "B.S. Computer Science",
        "major": "Computer Science",
        "graduationYear": 2024,
        "universityName": "Stanford University"
    }
    alice_degree_details_json = json.dumps(alice_degree_details)
    abe_policy_degree = f"student_id:{alice_kamc_id},degree_topic:B.S. Computer Science"
    encrypted_degree_data = abe_sim.encrypt(alice_degree_details_json, abe_policy_degree)
    degree_hash_payload = alice_degree_details_json + encrypted_degree_data 
    degree_hash_bytes = hashlib.sha256(degree_hash_payload.encode('utf-8')).digest()
    degree_hash_hex = degree_hash_bytes.hex()
    print(f"Alice's degree hash (hex): {degree_hash_hex}")
    OFF_CHAIN_ENCRYPTED_CREDENTIALS[degree_hash_hex] = encrypted_degree_data
    print(f"Encrypted degree data for {degree_hash_hex} stored off-chain.")

    print(f"Issuing credential for Alice ({alice_kamc_id}) by {uni_issuer_address_on_uni_chain}...")
    credential_issued_event_filter = university_registry_contract.events.CredentialIssued.create_filter(
        from_block='latest',
    )
    send_transaction(
        w3_uni,
        university_registry_contract.functions.issueCredential(
            alice_kamc_id, 
            "Bachelor of Science", 
            "Computer Science", 
            2024, 
            f"sim_storage://{degree_hash_hex}", 
            degree_hash_bytes 
        ),
        uni_issuer_pk_on_uni_chain
    )
    print("issueCredential transaction sent.")

    print("Waiting for CredentialIssued event on UNI-Chain...")
    issued_events = wait_for_event(credential_issued_event_filter)
    if not issued_events:
        print("CredentialIssued event not detected on UNI-Chain. Exiting issuance flow.")
        return
    
    credential_event_processed = False
    for event in issued_events:
        if event['args']['degreeHash'] == degree_hash_bytes and event['args']['studentId_on_KAMC_Chain'] == alice_kamc_id:
            print(f"[EVENT DETECTED on UNI-Chain] CredentialIssued for Alice (Degree Hash: {event['args']['degreeHash'].hex()})")
            credential_event_processed = True
            print("Relayer: Requesting ABE key for student Alice from KAMC-Chain...")
            # abe_key_req_student_event_filter = kamc_control_contract.events.ABEKeyGenerated.create_filter(
            #     fromBlock='latest', 
            #     argument_filters={'recipientId': alice_kamc_id}
            # )
            abe_key_req_student_event_filter = kamc_control_contract.events.ABEKeyReady.create_filter(
                from_block='latest',
                argument_filters={'requesterId_on_KAMC_Chain': alice_kamc_id}
            )
            send_transaction(
                w3_kamc,
                kamc_control_contract.functions.requestABEKeyGeneration(
                    alice_kamc_id, 
                    json.dumps([{"attribute": "student_id", "value": alice_kamc_id}, {"attribute": "degree_topic", "value": "B.S. Computer Science"}]), 
                    1 
                ),
                kamc_admin_pk 
            )
            print("ABEKeyGeneration request for student sent to KAMC-Chain.")

            print("Waiting for ABEKeyReady event for student on KAMC-Chain...")
            student_key_events = wait_for_event(abe_key_req_student_event_filter)
            if not student_key_events:
                print("ABEKeyGenerated event for student not detected on KAMC-Chain.")
                break 
            
            for sk_event in student_key_events:
                print(f"[EVENT DETECTED on KAMC-Chain] ABEKeyGenerated for Student {sk_event['args']['recipientId']}")
                student_abe_attributes_str = f"student_id:{alice_kamc_id},degree_topic:B.S. Computer Science"
                simulated_student_abe_sk = abe_sim.generate_secret_key(student_abe_attributes_str)
                OFF_CHAIN_ENCRYPTED_ABE_KEYS_STUDENT[alice_kamc_id] = simulated_student_abe_sk
                print(f"Simulated ABE secret key for Alice ({alice_kamc_id}) generated and stored off-chain: {simulated_student_abe_sk}")
            break 
    if not credential_event_processed:
        print("No matching CredentialIssued event found for the transaction or ABE key gen failed.")
        return

    print("Credential Issuance Flow complete.")

    # --- 3. Credential Verification Flow ---
    print("\n--- 3. Credential Verification Flow ---")
    verification_requester_contract = contracts["emp"]["VerificationRequester"]
    student_consent_contract = contracts["emp"]["StudentConsentRegistry"]

    print(f"Employer {google_kamc_id} requesting verification for degree hash {degree_hash_hex}...")
    verification_requested_event_filter = verification_requester_contract.events.VerificationRequested.create_filter(
        from_block='latest',
        argument_filters={'degreeHash': degree_hash_bytes, 'employerId_on_KAMC_Chain': google_kamc_id}
    )
    
    tx_receipt_vr = send_transaction(
        w3_emp,
        verification_requester_contract.functions.requestVerification(
            google_kamc_id, 
            alice_kamc_id,  
            degree_hash_bytes, 
            "Pre-employment screening"
        ),
        CONFIG["EMP_CHAIN"]["PRIVATE_KEY"] # Relayer/Employer on EMP chain
    )
    
    current_request_id = None
    for log_entry in tx_receipt_vr.get('logs', []):
        try:
            event_data_vr = verification_requester_contract.events.VerificationRequested().process_log(log_entry)
            current_request_id = event_data_vr['args']['requestId']
            print(f"Verification Request ID: {current_request_id}")
            break
        except Exception:
            pass
    if current_request_id is None:
        print("Could not get Verification Request ID. Exiting verification flow.")
        return

    print("Waiting for VerificationRequested event on EMP-Chain...")
    requested_events = wait_for_event(verification_requested_event_filter)
    if not requested_events:
        print("VerificationRequested event not detected. Exiting.")
        return

    verification_event_processed = False
    for event_vr in requested_events:
        if event_vr['args']['requestId'] == current_request_id:
            print(f"[EVENT DETECTED on EMP-Chain] VerificationRequested (ID: {current_request_id}) for Alice's degree by {google_kamc_id}")
            verification_event_processed = True
            print(f"Student {alice_kamc_id} (acting as {student_emp_chain_address} on EMP-Chain) granting consent with ZKP...")
            zkp_public_inputs_consent = {"degree_hash": degree_hash_hex, "employer_id": google_kamc_id, "request_id": current_request_id}
            zkp_private_witness_consent = {"student_id": alice_kamc_id, "degree_hash": degree_hash_hex, "action": "grant_consent", "degreeDetails": {"universityName": "Stanford University"} }
            # For ZKP, public inputs should include what's being proven against, e.g., university name if it's part of the proof statement.
            # The ZKP simulation's generate_proof expects public_inputs_str to contain 'asserted_university_name'.
            zkp_public_inputs_for_proof_gen = {"asserted_university_name": "Stanford University", **zkp_public_inputs_consent}
            consent_proof = zkp_sim.generate_proof(json.dumps(zkp_private_witness_consent), json.dumps(zkp_public_inputs_for_proof_gen))
            print(f"ZKP consent proof generated: {consent_proof}")

            consent_given_event_filter = student_consent_contract.events.ConsentGrantedWithZKP.create_filter(
                from_block='latest',
                argument_filters={'requestId': current_request_id}
            )
            send_transaction(
                w3_emp,
                student_consent_contract.functions.grantConsentWithZKP(
                    current_request_id,
                    alice_kamc_id,
                    degree_hash_bytes,
                    google_kamc_id,
                    json.dumps(zkp_public_inputs_consent).encode(), 
                    consent_proof.encode() 
                ),
                STUDENT_EMP_PK 
            )
            print("grantConsentWithZKP transaction sent.")

            print("Waiting for ConsentGrantedWithZKP event on EMP-Chain...")
            consent_events = wait_for_event(consent_given_event_filter)
            if not consent_events:
                print("ConsentGrantedWithZKP event not detected.")
                break 

            for event_cg in consent_events:
                print(f"[EVENT DETECTED on EMP-Chain] ConsentGrantedWithZKP for Request ID: {current_request_id}")
                is_consent_zkp_valid = zkp_sim.verify_proof(consent_proof, json.dumps(zkp_public_inputs_for_proof_gen))
                if not is_consent_zkp_valid:
                    print("Relayer: ZKP Consent Verification FAILED. Aborting.")
                    break 
                
                print("Relayer: ZKP Consent Verification SUCCESSFUL.")
                print(f"Relayer: Requesting ABE key for employer {google_kamc_id} from KAMC-Chain...")
                abe_key_req_employer_event_filter = kamc_control_contract.events.ABEKeyReady.create_filter(
                    from_block='latest',
                    argument_filters={'requesterId_on_KAMC_Chain': google_kamc_id, 'requestId': current_request_id} 
                )
                send_transaction(
                    w3_kamc,
                    kamc_control_contract.functions.requestABEKeyGenerationForVerification(
                        google_kamc_id, 
                        alice_kamc_id, 
                        degree_hash_bytes, 
                        current_request_id, 
                        json.dumps([{"attribute": "employer_id", "value": google_kamc_id}, {"attribute": "student_consent_for_degree", "value": degree_hash_hex}]) 
                    ),
                    kamc_admin_pk 
                )
                print("ABEKeyGeneration request for employer sent to KAMC-Chain.")

                print("Waiting for ABEKeyGenerated event for employer on KAMC-Chain...")
                employer_key_events = wait_for_event(abe_key_req_employer_event_filter)
                if not employer_key_events:
                    print("ABEKeyGenerated event for employer not detected.")
                    break 
                
                for ek_event in employer_key_events:
                    print(f"[EVENT DETECTED on KAMC-Chain] ABEKeyGenerated for Employer {ek_event['args']['recipientId']} (Request ID: {ek_event['args']['requestId']})")
                    employer_abe_attributes_str = f"employer_id:{google_kamc_id},student_consent_for_degree:{degree_hash_hex}"
                    simulated_employer_abe_sk = abe_sim.generate_secret_key(employer_abe_attributes_str)
                    OFF_CHAIN_ENCRYPTED_ABE_KEYS_EMPLOYER[current_request_id] = simulated_employer_abe_sk
                    print(f"Simulated ABE secret key for Employer ({google_kamc_id}) generated and stored off-chain for request {current_request_id}: {simulated_employer_abe_sk}")

                    retrieved_encrypted_degree_data = OFF_CHAIN_ENCRYPTED_CREDENTIALS.get(degree_hash_hex)
                    if not retrieved_encrypted_degree_data:
                        print(f"ERROR: Encrypted degree data not found off-chain for hash {degree_hash_hex}")
                        break 
                    
                    print("Employer: Attempting to decrypt degree details with ABE key...")
                    decrypted_degree_info = abe_sim.decrypt(retrieved_encrypted_degree_data, simulated_employer_abe_sk)
                    
                    verification_status = False
                    verification_comment = "Decryption failed or policy not met."
                    if decrypted_degree_info:
                        print(f"Employer: Decryption SUCCESSFUL. Degree Details: {decrypted_degree_info}")
                        verification_status = True
                        verification_comment = "Credential verified successfully after decryption."
                    else:
                        print("Employer: Decryption FAILED. Policy might not be satisfied by employer's ABE key attributes.")

                    print(f"Relayer: Submitting verification result for Request ID {current_request_id} to EMP-Chain...")
                    verification_completed_event_filter = verification_requester_contract.events.VerificationCompleted.create_filter(
                        from_block='latest',
                        argument_filters={'requestId': current_request_id}
                    )
                    send_transaction(
                        w3_emp,
                        verification_requester_contract.functions.submitVerificationResult(
                            current_request_id,
                            verification_status,
                            verification_comment
                        ),
                        CONFIG["EMP_CHAIN"]["PRIVATE_KEY"] # Relayer on EMP chain
                    )
                    print("submitVerificationResult transaction sent.")

                    print("Waiting for VerificationCompleted event on EMP-Chain...")
                    completed_events = wait_for_event(verification_completed_event_filter)
                    if completed_events:
                        for final_event in completed_events:
                            print(f"[EVENT DETECTED on EMP-Chain] VerificationCompleted for Request ID {final_event['args']['requestId']}. Status: {final_event['args']['verificationStatus']}")
                    else:
                        print("VerificationCompleted event not detected.")
                    break 
                break 
            break 
    if not verification_event_processed:
        print("No matching VerificationRequested event found or subsequent steps failed.")
        return

    print("Credential Verification Flow complete.")
    print("\n--- Demo Finished ---")

if __name__ == "__main__":
    connected_chains = True
    if not w3_uni.is_connected():
        print("UNI-Chain is not connected. Please ensure Hardhat node is running on port 8545.")
        connected_chains = False
    if not w3_emp.is_connected():
        print("EMP-Chain is not connected. Please ensure Hardhat node is running on port 8546.")
        connected_chains = False
    if not w3_kamc.is_connected():
        print("KAMC-Chain is not connected. Please ensure Hardhat node is running on port 8547.")
        connected_chains = False

    if connected_chains:
        print("All chains connected successfully.")
        try:
            main_demo()
        except Exception as e:
            print(f"An error occurred during the demo: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("Please fix chain connectivity issues before running the demo.")


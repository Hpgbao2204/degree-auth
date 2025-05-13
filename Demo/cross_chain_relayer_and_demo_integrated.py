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
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware # For PoA chains like Hardhat default

# Import crypto simulation modules
from crypto_simulations.abe_simulation import ABESimulation
from crypto_simulations.mpc_simulation import MPCSimulation
from crypto_simulations.tss_simulation import TSSSimulation
from crypto_simulations.zkp_simulation import ZKPSimulation

# --- Configuration (User Provided or Default) ---
CONFIG = {
    "UNI_CHAIN": {
        "RPC_URL": "http://127.0.0.1:8545",
        "UniversityRegistry": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
        "ACCOUNT_ADDRESS": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "PRIVATE_KEY": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    },
    "EMP_CHAIN": {
        "RPC_URL": "http://127.0.0.1:8546",
        "VerificationRequester": "0x8464135c8F25Da09e49BC8782676a84730C318bC",
        "StudentConsentRegistry": "0x71C95911E9a5D330f4D621842EC243EE1343292e",
        "ACCOUNT_ADDRESS": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "PRIVATE_KEY": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    },
    "KAMC_CHAIN": {
        "RPC_URL": "http://127.0.0.1:8547",
        "EntityRegistry": "0xC469e7aE4aD962c30c7111dc580B4adbc7E914DD",
        "KAMCControl": "0x43ca3D2C94be00692D207C6A1e60D8B325c6f12f",
        "ACCOUNT_ADDRESS": "0xcd3B766CCDd6AE721141F452C550Ca635964ce71", # account 15
        "PRIVATE_KEY": "0x8166f546bab6da521a8369cab06c5d2b9e46670292d85c875ee9ec20e84ffb61"
    }
}

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
    
    # Check if content starts with "abi": and fix the format
    if content.strip().startswith('"abi":'):
        try:
            # Wrap in curly braces to make it a valid JSON object
            wrapped_content = '{' + content + '}'
            parsed = json.loads(wrapped_content)
            return parsed["abi"]
        except json.JSONDecodeError:
            pass

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
        # Estimate gas
        estimated_gas = contract_function.estimate_gas(txn_params)
        txn_params['gas'] = estimated_gas
    except Exception as e:
        print(f"Gas estimation failed: {e}. Using default gas limit 3,000,000")
        txn_params['gas'] = 3000000 # Default gas limit

    transaction = contract_function.build_transaction(txn_params)
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=account_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"Transaction sent: {tx_hash.hex()}")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    if tx_receipt.status == 0:
        print(f"Transaction failed: {tx_receipt}")
        raise Exception(f"Transaction failed: {tx_receipt.transactionHash.hex()}")
    print(f"Transaction successful: {tx_receipt.transactionHash.hex()}")
    return tx_receipt

def wait_for_event(event_filter, timeout=120, poll_interval=2):
    start_time = time.time()
    while time.time() < start_time + timeout:
        new_events = event_filter.get_new_entries()
        if new_events:
            return new_events
        time.sleep(poll_interval)
    print("Timeout waiting for event.")
    return []

# --- Main Demo Logic ---
def main_demo():
    print("\n--- Starting Event-Driven Cross-Chain Education Credential Demo ---")

    # Define participants (using KAMC chain addresses for registration)
    uni_owner_addr = CONFIG["UNI_CHAIN"]["ACCOUNT_ADDRESS"]
    uni_kamc_chain_addr = CONFIG["KAMC_CHAIN"]["ACCOUNT_ADDRESS"] # For simplicity, KAMC deployer registers Uni
    uni_pk = CONFIG["KAMC_CHAIN"]["PRIVATE_KEY"]

    student_addr = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65" # Hardhat account 4
    student_pk = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" # Hardhat account 3 PK
    
    employer_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" # Hardhat account 0
    employer_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Hardhat account 0 PK

    # --- 1. Entity Registration on KAMC-Chain ---
    print("\n--- 1. Entity Registration on KAMC-Chain ---")
    entity_registry_contract = contracts["kamc"]["EntityRegistry"]
    kamc_control_contract = contracts["kamc"]["KAMCControl"]

    # Register University
    print("Registering University (Stanford)...")
    tx_receipt_uni_reg = send_transaction(
        w3_kamc,
        entity_registry_contract.functions.registerUniversity(
            "Stanford University", 
            CONFIG["UNI_CHAIN"]["UniversityRegistry"], # Address of UniRegistry on UNI-Chain (for reference)
            "Top Tier University"
        ),
        uni_pk # KAMC chain deployer/owner registers the uni
    )
    # We need to get the emitted entityId for Stanford
    stanford_kamc_id = ""
    for log in tx_receipt_uni_reg['logs']:
        try:
            event_data = entity_registry_contract.events.EntityRegistered().process_log(log)
            if event_data['args']['name'] == "Stanford University":
                stanford_kamc_id = event_data['args']['entityId_on_KAMC_Chain']
                print(f"Stanford KAMC ID: {stanford_kamc_id}")
                break
        except Exception:
            pass
    if not stanford_kamc_id:
        print("Could not retrieve Stanford KAMC ID from event. Exiting.")
        return

    # Register Student
    print("Registering Student (Alice)...")
    # For student, their KAMC primary address is their main identifier for registration
    # The student_pk here is for the KAMC chain if Alice were to register herself.
    # For simplicity, let's assume KAMC admin/deployer registers Alice.
    student_address = w3_kamc.eth.account.from_key(student_pk).address
    alice_kamc_id = None

    try:
        # Try to get existing entity ID by address
        alice_kamc_id = entity_registry_contract.functions.getEntityIdByPrimaryAddress(student_address).call()
        print(f"Student address {student_address} already registered with ID: {alice_kamc_id}")
    except Exception:
        # If no entity exists, proceed with registration
        tx_receipt_stu_reg = send_transaction(
            w3_kamc,
            entity_registry_contract.functions.registerStudent("Alice Wonderland", "CS Student"),
            student_pk # Student uses their own PK on KAMC chain
        )
        
        # Extract entity ID from registration event
        for log in tx_receipt_stu_reg['logs']:
            try:
                event_data = entity_registry_contract.events.EntityRegistered().process_log(log)
                if event_data['args']['name'] == "Alice Wonderland":
                    alice_kamc_id = event_data['args']['entityId_on_KAMC_Chain']
                    print(f"Alice KAMC ID: {alice_kamc_id}")
                    break
            except Exception:
                pass

    if not alice_kamc_id:
        print("Could not retrieve Alice KAMC ID. Exiting.")
        return

    # Register Employer
    print("Registering Employer (Google)...")
    tx_receipt_emp_reg = send_transaction(
        w3_kamc,
        entity_registry_contract.functions.registerEmployer(
            "Google LLC", 
            CONFIG["EMP_CHAIN"]["VerificationRequester"], # Address of VerifReq on EMP-Chain (for reference)
            "Tech Company"
        ),
        employer_pk # Employer uses their own PK on KAMC chain
    )
    google_kamc_id = ""
    for log in tx_receipt_emp_reg['logs']:
        try:
            event_data = entity_registry_contract.events.EntityRegistered().process_log(log)
            if event_data['args']['name'] == "Google LLC":
                google_kamc_id = event_data['args']['entityId_on_KAMC_Chain']
                print(f"Google KAMC ID: {google_kamc_id}")
                break
        except Exception:
            pass
    if not google_kamc_id:
        print("Could not retrieve Google KAMC ID from event. Exiting.")
        return
        
    # Set KAMC Control parameters (simulated)
    print("Setting KAMC Control parameters (TSS PubKey, ABE PubParams)...")
    send_transaction(
        w3_kamc,
        kamc_control_contract.functions.updateTSSPublicKey(tss_sim.public_key().encode()), # bytes
        uni_pk # KAMC deployer/owner
    )
    send_transaction(
        w3_kamc,
        kamc_control_contract.functions.updateABEPublicParams(json.dumps(abe_sim.get_public_params()).encode()), # bytes
        uni_pk # KAMC deployer/owner
    )
    print("KAMC Setup complete.")

    # --- 2. Credential Issuance Flow ---
    print("\n--- 2. Credential Issuance Flow ---")
    university_registry_contract = contracts["uni"]["UniversityRegistry"]
    
    # University needs to be registered on its own UniversityRegistry contract first (by owner)
    # The owner of UniversityRegistry is CONFIG["UNI_CHAIN"]["ACCOUNT_ADDRESS"]
    print(f"Registering {stanford_kamc_id} on UniversityRegistry on UNI-Chain...")
    # The address used to call registerUniversity on UNI-Chain must be the KAMC ID's specificChainAddress if that's how it's designed
    # Or, the UniversityRegistry owner (deployer) registers the KAMC ID's primary KAMC address.
    # For this demo, let's assume the UniversityRegistry owner (deployer of UniRegistry) registers itself as a valid university.
    # The address that calls issueCredential must be a registered university.
    # Let's use the deployer of UniRegistry as the 'university' for issuing.
    uni_issuer_address_on_uni_chain = CONFIG["UNI_CHAIN"]["ACCOUNT_ADDRESS"]
    uni_issuer_pk_on_uni_chain = CONFIG["UNI_CHAIN"]["PRIVATE_KEY"]

    try:
        # Check if already registered, if not, register.
        # This is a simplification; a real system would have a clear mapping.
        is_uni_registered = university_registry_contract.functions.registeredUniversities(uni_issuer_address_on_uni_chain).call()
        if not is_uni_registered:
            print(f"University {uni_issuer_address_on_uni_chain} not registered on UniRegistry. Registering...")
            send_transaction(
                w3_uni,
                university_registry_contract.functions.registerUniversity(uni_issuer_address_on_uni_chain),
                uni_issuer_pk_on_uni_chain # Owner of UniRegistry registers an issuer
            )
            print(f"University {uni_issuer_address_on_uni_chain} registered.")
        else:
            print(f"University {uni_issuer_address_on_uni_chain} already registered on UniRegistry.")
    except Exception as e:
        print(f"Error during university registration on UniRegistry: {e}")
        return

    # Prepare credential data
    alice_degree_details = {
        "studentName": "Alice Wonderland",
        "degree": "B.S. Computer Science",
        "major": "Computer Science",
        "graduationYear": 2024,
        "universityName": "Stanford University"
    }
    alice_degree_details_json = json.dumps(alice_degree_details)
    
    # ABE policy for Alice's degree (example)
    abe_policy_degree = f"student_id:{alice_kamc_id} AND degree_topic:B.S. Computer Science"
    encrypted_degree_data = abe_sim.encrypt(alice_degree_details_json, abe_policy_degree)
    
    degree_hash_payload = alice_degree_details_json + encrypted_degree_data # Simplified hash source
    degree_hash_bytes = hashlib.sha256(degree_hash_payload.encode('utf-8')).digest()
    degree_hash_hex = degree_hash_bytes.hex()
    print(f"Alice's degree hash (bytes): {degree_hash_bytes}")
    print(f"Alice's degree hash (hex): {degree_hash_hex}")

    OFF_CHAIN_ENCRYPTED_CREDENTIALS[degree_hash_hex] = encrypted_degree_data
    print(f"Encrypted degree data for {degree_hash_hex} stored off-chain.")

    # University issues credential on UNI-Chain
    print(f"Issuing credential for Alice ({alice_kamc_id}) by {uni_issuer_address_on_uni_chain}...")
    
    # Event filter for CredentialIssued
    credential_issued_event_filter = university_registry_contract.events.CredentialIssued.create_filter(
        fromBlock='latest'
    )

    send_transaction(
        w3_uni,
        university_registry_contract.functions.issueCredential(
            alice_kamc_id, # studentId_on_KAMC_Chain
            "Bachelor of Science", # credentialType
            "Computer Science", # major
            2024, # graduationYear
            f"sim_storage://{degree_hash_hex}", # offChainEncryptedDataPointer
            degree_hash_bytes # degreeHash (bytes32)
        ),
        uni_issuer_pk_on_uni_chain
    )
    print("issueCredential transaction sent.")

    # Wait for CredentialIssued event
    print("Waiting for CredentialIssued event on UNI-Chain...")
    issued_events = wait_for_event(credential_issued_event_filter, timeout=30)
    if not issued_events:
        print("CredentialIssued event not detected on UNI-Chain. Exiting issuance flow.")
        return
    
    for event in issued_events:
        if event['args']['degreeHash'] == degree_hash_bytes and event['args']['studentId_on_KAMC_Chain'] == alice_kamc_id:
            print(f"[EVENT DETECTED on UNI-Chain] CredentialIssued for Alice (Degree Hash: {event['args']['degreeHash'].hex()})")
            # Relayer action: Request ABE key for student from KAMC
            print("Relayer: Requesting ABE key for student Alice from KAMC-Chain...")
            
            abe_key_req_student_event_filter = kamc_control_contract.events.ABEKeyGenerated.create_filter(
                fromBlock='latest', 
                argument_filters={'recipientId': alice_kamc_id}
            )
            
            send_transaction(
                w3_kamc,
                kamc_control_contract.functions.requestABEKeyGeneration(
                    alice_kamc_id, # recipientId
                    json.dumps([{"attribute": "student_id", "value": alice_kamc_id}, {"attribute": "degree_topic", "value": "B.S. Computer Science"}]), # attributes_json
                    1 # Key type: 1 for student, 2 for employer (example)
                ),
                uni_pk # KAMC chain admin/relayer initiates this
            )
            print("ABEKeyGeneration request for student sent to KAMC-Chain.")

            print("Waiting for ABEKeyGenerated event for student on KAMC-Chain...")
            student_key_events = wait_for_event(abe_key_req_student_event_filter, timeout=30)
            if not student_key_events:
                print("ABEKeyGenerated event for student not detected on KAMC-Chain.")
                break # Break from issued_events loop
            
            for sk_event in student_key_events:
                print(f"[EVENT DETECTED on KAMC-Chain] ABEKeyGenerated for Student {sk_event['args']['recipientId']}")
                # Simulate MPC for key generation (as KAMCControl would trigger this)
                student_abe_attributes = [{"attribute": "student_id", "value": alice_kamc_id}, {"attribute": "degree_topic", "value": "B.S. Computer Science"}]
                simulated_student_abe_sk = mpc_sim.simulate_secure_computation(
                    "generate_abe_user_sk", 
                    inputs=student_abe_attributes # Simplified input
                )
                OFF_CHAIN_ENCRYPTED_ABE_KEYS_STUDENT[alice_kamc_id] = simulated_student_abe_sk
                print(f"Simulated ABE secret key for Alice ({alice_kamc_id}) generated via MPC and stored off-chain.")
            break # Found the matching CredentialIssued event
    else:
        print("No matching CredentialIssued event found for the transaction.")
        return

    print("Credential Issuance Flow complete.")

    # --- 3. Credential Verification Flow ---
    print("\n--- 3. Credential Verification Flow ---")
    verification_requester_contract = contracts["emp"]["VerificationRequester"]
    student_consent_contract = contracts["emp"]["StudentConsentRegistry"]

    # Employer requests verification on EMP-Chain
    print(f"Employer {google_kamc_id} requesting verification for degree hash {degree_hash_hex}...")
    
    verification_requested_event_filter = verification_requester_contract.events.VerificationRequested.create_filter(
        fromBlock='latest',
        argument_filters={'degreeHash': degree_hash_bytes, 'employerId_on_KAMC_Chain': google_kamc_id}
    )
    
    tx_receipt_vr = send_transaction(
        w3_emp,
        verification_requester_contract.functions.requestVerification(
            google_kamc_id, # employerId_on_KAMC_Chain
            alice_kamc_id,  # studentId_on_KAMC_Chain
            degree_hash_bytes, # degreeHash_on_UNI_Chain
            "Pre-employment screening"
        ),
        CONFIG["EMP_CHAIN"]["PRIVATE_KEY"] # Employer's PK on EMP-Chain (using deployer for simplicity)
    )
    
    current_request_id = None
    for log_vr in tx_receipt_vr['logs']:
        try:
            event_data_vr = verification_requester_contract.events.VerificationRequested().process_log(log_vr)
            current_request_id = event_data_vr['args']['requestId']
            print(f"Verification Request ID: {current_request_id}")
            break
        except Exception:
            pass
    if current_request_id is None:
        print("Could not get Verification Request ID. Exiting verification flow.")
        return

    print("Waiting for VerificationRequested event on EMP-Chain...")
    requested_events = wait_for_event(verification_requested_event_filter, timeout=30)
    if not requested_events:
        print("VerificationRequested event not detected. Exiting.")
        return

    for event_vr in requested_events:
        if event_vr['args']['requestId'] == current_request_id:
            print(f"[EVENT DETECTED on EMP-Chain] VerificationRequested (ID: {current_request_id}) for Alice's degree by {google_kamc_id}")
            
            # Student grants consent with ZKP on EMP-Chain
            print(f"Student {alice_kamc_id} granting consent with ZKP...")
            zkp_public_inputs_consent = {"degree_hash": degree_hash_hex, "employer_id": google_kamc_id, "request_id": current_request_id}
            zkp_private_witness_consent = {"student_id": alice_kamc_id, "degree_hash": degree_hash_hex, "action": "grant_consent"}
            consent_proof = zkp_sim.generate_proof(zkp_private_witness_consent, zkp_public_inputs_consent)
            print(f"ZKP consent proof generated: {consent_proof}")

            consent_given_event_filter = student_consent_contract.events.ConsentGrantedWithZKP.create_filter(
                fromBlock='latest',
                argument_filters={'requestId': current_request_id}
            )

            send_transaction(
                w3_emp,
                student_consent_contract.functions.grantConsentWithZKP(
                    current_request_id,
                    alice_kamc_id,
                    degree_hash_bytes,
                    google_kamc_id,
                    json.dumps(zkp_public_inputs_consent).encode(), # publicInputsBytes
                    consent_proof.encode() # proofBytes
                ),
                student_pk # Student's PK on EMP-Chain
            )
            print("grantConsentWithZKP transaction sent.")

            print("Waiting for ConsentGrantedWithZKP event on EMP-Chain...")
            consent_events = wait_for_event(consent_given_event_filter, timeout=30)
            if not consent_events:
                print("ConsentGrantedWithZKP event not detected.")
                break # from requested_events loop

            for event_cg in consent_events:
                print(f"[EVENT DETECTED on EMP-Chain] ConsentGrantedWithZKP for Request ID: {current_request_id}")
                # Relayer verifies ZKP (off-chain)
                is_consent_zkp_valid = zkp_sim.verify_proof(consent_proof, zkp_public_inputs_consent)
                if not is_consent_zkp_valid:
                    print("Relayer: ZKP Consent Verification FAILED. Aborting.")
                    # Optionally submit a failed verification result
                    break # from consent_events loop
                
                print("Relayer: ZKP Consent Verification SUCCESSFUL.")
                # Relayer: Request ABE key for employer from KAMC
                print("Relayer: Requesting ABE key for employer {google_kamc_id} from KAMC-Chain...")
                
                abe_key_req_employer_event_filter = kamc_control_contract.events.ABEKeyGenerated.create_filter(
                    fromBlock='latest',
                    argument_filters={'recipientId': google_kamc_id, 'requestId': current_request_id} # Assuming KAMCControl emits requestId
                )

                send_transaction(
                    w3_kamc,
                    kamc_control_contract.functions.requestABEKeyGenerationForVerification(
                        google_kamc_id, # recipientId (employer)
                        alice_kamc_id, # studentId
                        degree_hash_bytes, # degreeHash
                        current_request_id, # original EMP-Chain request ID for linking
                        json.dumps([{"attribute": "employer_id", "value": google_kamc_id}, {"attribute": "student_consent_for_degree", "value": degree_hash_hex}]) # attributes_json
                    ),
                    uni_pk # KAMC chain admin/relayer
                )
                print("ABEKeyGeneration request for employer sent to KAMC-Chain.")

                print("Waiting for ABEKeyGenerated event for employer on KAMC-Chain...")
                employer_key_events = wait_for_event(abe_key_req_employer_event_filter, timeout=30)
                if not employer_key_events:
                    print("ABEKeyGenerated event for employer not detected.")
                    break # from consent_events loop
                
                for ek_event in employer_key_events:
                    print(f"[EVENT DETECTED on KAMC-Chain] ABEKeyGenerated for Employer {ek_event['args']['recipientId']} (Request ID: {ek_event['args']['requestId']})")
                    employer_abe_attributes = [{"attribute": "employer_id", "value": google_kamc_id}, {"attribute": "student_consent_for_degree", "value": degree_hash_hex}]
                    simulated_employer_abe_sk = mpc_sim.simulate_secure_computation(
                        "generate_abe_user_sk", 
                        inputs=employer_abe_attributes
                    )
                    OFF_CHAIN_ENCRYPTED_ABE_KEYS_EMPLOYER[current_request_id] = simulated_employer_abe_sk
                    print(f"Simulated ABE secret key for Employer ({google_kamc_id}) generated via MPC and stored off-chain for request {current_request_id}.")

                    # Employer fetches encrypted credential and decrypts
                    retrieved_encrypted_degree_data = OFF_CHAIN_ENCRYPTED_CREDENTIALS.get(degree_hash_hex)
                    if not retrieved_encrypted_degree_data:
                        print(f"ERROR: Encrypted degree data not found off-chain for hash {degree_hash_hex}")
                        break # from employer_key_events loop
                    
                    print("Employer: Attempting to decrypt degree details with ABE key...")
                    decrypted_degree_info = abe_sim.decrypt(retrieved_encrypted_degree_data, simulated_employer_abe_sk)
                    
                    verification_status = False
                    verification_comment = "Decryption failed or policy not met."
                    if decrypted_degree_info:
                        print(f"Employer: Decryption SUCCESSFUL. Degree Details: {decrypted_degree_info}")
                        # Further validation of decrypted_degree_info against request can be done here
                        verification_status = True
                        verification_comment = "Credential verified successfully after decryption."
                    else:
                        print("Employer: Decryption FAILED. Policy might not be satisfied by employer's ABE key attributes.")

                    # Relayer submits verification result to EMP-Chain
                    print(f"Relayer: Submitting verification result for Request ID {current_request_id} to EMP-Chain...")
                    verification_completed_event_filter = verification_requester_contract.events.VerificationCompleted.create_filter(
                        fromBlock='latest',
                        argument_filters={'requestId': current_request_id}
                    )
                    send_transaction(
                        w3_emp,
                        verification_requester_contract.functions.submitVerificationResult(
                            current_request_id,
                            verification_status,
                            verification_comment
                        ),
                        CONFIG["EMP_CHAIN"]["PRIVATE_KEY"] # Relayer's PK on EMP-Chain (using deployer for simplicity)
                    )
                    print("submitVerificationResult transaction sent.")

                    print("Waiting for VerificationCompleted event on EMP-Chain...")
                    completed_events = wait_for_event(verification_completed_event_filter, timeout=30)
                    if completed_events:
                        for final_event in completed_events:
                             print(f"[EVENT DETECTED on EMP-Chain] VerificationCompleted for Request ID {final_event['args']['requestId']}. Status: {final_event['args']['verificationStatus']}")
                    else:
                        print("VerificationCompleted event not detected.")
                    break # from employer_key_events loop
                break # from consent_events loop
            break # from requested_events loop
    else:
        print("No matching VerificationRequested event found for the transaction.")
        return

    print("Credential Verification Flow complete.")
    print("\n--- Demo Finished ---")

if __name__ == "__main__":
    if not all(w3_instance.is_connected() for w3_instance in [w3_uni, w3_emp, w3_kamc]):
        print("One or more chains are not connected. Please ensure Hardhat nodes are running correctly.")
    else:
        print("All chains connected successfully.")
        try:
            main_demo()
        except Exception as e:
            print(f"An error occurred during the demo: {e}")
            import traceback
            traceback.print_exc()


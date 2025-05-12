# /home/ubuntu/crypto_simulations/zkp_simulation.py

import hashlib
import json

class ZKPSimulation:
    def __init__(self):
        # In a real ZKP system, there would be a setup phase to generate proving and verification keys.
        # These keys would be specific to a particular circuit/statement.
        self.proving_key_sim = "zkp_proving_key_simulated_for_credential_ownership"
        self.verification_key_sim = "zkp_verification_key_simulated_for_credential_ownership"
        print(f"[ZKP SIM] Setup complete. Proving Key: {self.proving_key_sim}, Verification Key: {self.verification_key_sim}")

    def generate_proof(self, private_witness_data_str, public_inputs_str):
        """
        Simulates generating a ZKP.
        - private_witness_data_str: Data known only to the prover (e.g., student ID, full degree details).
        - public_inputs_str: Data known to both prover and verifier (e.g., hash of the degree, university name).
        The proof shows that the prover knows private_witness that, along with public_inputs, satisfies some statement.
        """
        print(f"[ZKP SIM] Generating proof with private witness (first 50 chars): {private_witness_data_str[:50]}... and public inputs: {public_inputs_str}")
        
        # Parse the inputs to verify consistency
        private_data = json.loads(private_witness_data_str)
        public_inputs = json.loads(public_inputs_str)
        
        # Check if the university name in private data matches the asserted university name
        actual_university = private_data.get("degreeDetails", {}).get("universityName")
        asserted_university = public_inputs.get("asserted_university_name")
        
        if actual_university != asserted_university:
            print(f"[ZKP SIM] Error: University mismatch. Actual: {actual_university}, Asserted: {asserted_university}")
            return "zkp_proof_failed_due_to_data_inconsistency"
        
        # For simulation, the proof is just a hash of the inputs and a fixed string.
        # In reality, this is a complex cryptographic object.
        proof_content = {
            "private_witness_hash_sim": hashlib.sha256(private_witness_data_str.encode()).hexdigest(),
            "public_inputs": public_inputs_str,
            "statement_sim": f"Prover knows witness for public inputs {public_inputs_str}",
            "generated_with_pk": self.proving_key_sim
        }
        proof = f"zkp_proof_({json.dumps(proof_content)})"
        print(f"[ZKP SIM] Proof generated successfully.")
        return proof

    def verify_proof(self, proof_str, public_inputs_str):
        """
        Simulates verifying a ZKP.
        - proof_str: The ZKP provided by the prover.
        - public_inputs_str: The public inputs the proof is for.
        The verification uses the verification_key_sim.
        """
        print(f"[ZKP SIM] Verifying proof for public inputs: {public_inputs_str}")
        
        try:
            # Simulate parsing the proof (highly simplified)
            if not proof_str.startswith("zkp_proof_(") or not proof_str.endswith(")"):
                print("[ZKP SIM] Verification failed: Invalid proof format.")
                return False

            proof_json_str = proof_str.replace("zkp_proof_(", "").rstrip(")")
            proof_content = json.loads(proof_json_str)

            # Check if public inputs match and if it was generated with the expected proving key (simulated check)
            if proof_content.get("public_inputs") == public_inputs_str and \
              proof_content.get("generated_with_pk") == self.proving_key_sim:
                print(f"[ZKP SIM] Proof verification successful for public inputs: {public_inputs_str}")
                return True
            else:
                print("[ZKP SIM] Verification failed: Public inputs mismatch or wrong proving key used.")
                return False
        except Exception as e:
            print(f"[ZKP SIM] Verification error: {e}")
            return False

if __name__ == '__main__':
    zkp_system = ZKPSimulation()

    # Example: Student wants to prove they own a degree from "Stanford" with a specific hash,
    # without revealing their full name or student ID initially.
    
    degree_data = {
        "program": "BSc Computer Science",
        "graduationYear": 2024,
        "universityName": "Stanford University"
    }
    
    # Private witness known to student
    alice_private_data = json.dumps({
        "studentFullName": "Alice Wonderland",
        "studentId": "ALICE123",
        "degreeDetails": degree_data,
        "secretSalt": "a_very_secret_salt_value"
    })
    
    # Public inputs known to verifier (e.g., Employer)
    # The degree_hash would be something the employer obtained from the University's public ledger (UNI-Chain).
    # The university_name might also be public or part of the verification request.
    public_degree_hash = hashlib.sha256((json.dumps(degree_data)).encode()).hexdigest() # Simplified hash for demo
    # public_university_name = "Stanford University"
    public_university_name = "Stanford University"
    
    alice_public_inputs = json.dumps({
        "asserted_degree_hash": public_degree_hash,
        "asserted_university_name": public_university_name
    })

    # Student generates proof
    proof = zkp_system.generate_proof(alice_private_data, alice_public_inputs)
    print(f"Generated ZKP: {proof[:100]}...")

    # Employer (or relayer) verifies proof
    is_valid = zkp_system.verify_proof(proof, alice_public_inputs)
    print(f"ZKP Verification Result: {is_valid}")

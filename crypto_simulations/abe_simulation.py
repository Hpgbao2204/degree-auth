# /home/ubuntu/crypto_simulations/abe_simulation.py

import json

class ABESimulation:
    def __init__(self):
        self.master_secret_key = "abe_msk_simulated"
        self.public_parameters = "abe_pp_simulated"
        print("[ABE SIM] Setup complete. Master Secret Key and Public Parameters generated.")

    def generate_secret_key(self, user_attributes_str):
        """Generates a secret key for a user based on their attributes."""
        # In a real ABE system, attributes would be a list or set.
        # Here, user_attributes_str is a string like "student_id:STU-1" or "employer_id:EMP-1,student_consent_for_degree:0x..."
        print(f"[ABE SIM] Generating secret key for attributes: {user_attributes_str}")
        # This is highly simplified. Real ABE key generation is complex.
        return f"sk_abe_for_({user_attributes_str})_with_({self.master_secret_key})"

    def encrypt(self, plaintext_data_str, policy_str):
        """Encrypts data under a given access policy string."""
        # Policy_str might be a boolean expression of attributes, e.g., "(role:doctor AND department:cardiology) OR role:admin"
        # For simplicity, we assume the policy_str directly matches the attributes used for keygen for successful decryption.
        print(f"[ABE SIM] Encrypting data: {plaintext_data_str[:50]}... under policy: {policy_str}")
        # Real ABE encryption involves complex pairing-based cryptography.
        ciphertext = {
            "policy": policy_str,
            "encrypted_content": f"abe_encrypted_version_of({plaintext_data_str})_under_policy({policy_str})",
            "pp": self.public_parameters
        }
        return json.dumps(ciphertext) # Return as a JSON string for storage/transmission

    def decrypt(self, ciphertext_str, user_secret_key_str):
        """Decrypts data if the user's secret key attributes satisfy the ciphertext's policy."""
        print(f"[ABE SIM] Attempting to decrypt with key: {user_secret_key_str}")
        try:
            ciphertext = json.loads(ciphertext_str)
            policy = ciphertext.get("policy")
            encrypted_content = ciphertext.get("encrypted_content")

            # Highly simplified policy check: Does the key contain the policy string?
            # In a real system, this involves complex attribute matching and cryptographic operations.
            # Example: user_secret_key_str = "sk_abe_for_(student_id:STU-1)_with_(abe_msk_simulated)"
            #          policy = "student_id:STU-1"
            # This simplistic check assumes the key was generated for attributes that directly satisfy the policy.
            # A more robust simulation would parse attributes from the key and policy and compare them.
            
            # Extract attributes from key (very simplified)
            key_attributes_part = user_secret_key_str.split("_with_")[0].replace("sk_abe_for_(", "").replace(")", "")
            
            # Simple check: if policy is a substring of key attributes part
            # This is a very loose check for simulation purposes.
            if policy in key_attributes_part:
                print(f"[ABE SIM] Policy {policy} satisfied by key attributes {key_attributes_part}. Decryption successful.")
                # Extract original data (very simplified)
                original_data = encrypted_content.replace(f"abe_encrypted_version_of(", "").replace(f")_under_policy({policy})", "")
                return original_data
            else:
                print(f"[ABE SIM] Policy {policy} NOT satisfied by key attributes {key_attributes_part}. Decryption failed.")
                return None
        except Exception as e:
            print(f"[ABE SIM] Decryption error: {e}")
            return None

if __name__ == '__main__':
    abe_system = ABESimulation()
    
    # Test Key Generation
    student_attrs = "student_id:STU-1,role:student"
    student_sk = abe_system.generate_secret_key(student_attrs)
    print(f"Student Secret Key: {student_sk}")

    employer_attrs_with_consent = "employer_id:EMP-1,role:employer,consent_for_degree:0x123abc"
    employer_sk = abe_system.generate_secret_key(employer_attrs_with_consent)
    print(f"Employer Secret Key: {employer_sk}")

    # Test Encryption
    degree_data = json.dumps({"studentName": "Alice", "degree": "BSc CS", "grade": "A"})
    # Policy: Only student STU-1 OR an employer with consent for degree 0x123abc can decrypt
    # For simplicity, we'll encrypt with a policy that matches one of the keys.
    policy_for_student = "student_id:STU-1"
    policy_for_employer = "employer_id:EMP-1,consent_for_degree:0x123abc"

    encrypted_data_for_student = abe_system.encrypt(degree_data, policy_for_student)
    print(f"Encrypted for Student: {encrypted_data_for_student}")

    encrypted_data_for_employer = abe_system.encrypt(degree_data, policy_for_employer)
    print(f"Encrypted for Employer: {encrypted_data_for_employer}")

    # Test Decryption
    decrypted_by_student = abe_system.decrypt(encrypted_data_for_student, student_sk)
    print(f"Decrypted by Student: {decrypted_by_student}")

    decrypted_by_employer = abe_system.decrypt(encrypted_data_for_employer, employer_sk)
    print(f"Decrypted by Employer: {decrypted_by_employer}")
    
    # Test failed decryption (student key for employer policy)
    failed_decryption = abe_system.decrypt(encrypted_data_for_employer, student_sk)
    print(f"Failed Decryption (Student key for Employer policy): {failed_decryption}")

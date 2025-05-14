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
            policy_str = ciphertext.get("policy")
            encrypted_content = ciphertext.get("encrypted_content")

            # Extract attributes from key string
            # Example user_secret_key_str: "sk_abe_for_(['student_id:STU-2', 'degree_topic:B.S. Computer Science'])_with_(abe_msk_simulated)"
            key_attrs_raw_part = user_secret_key_str.split("_with_")[0]
            key_attrs_str_list_format = key_attrs_raw_part.replace("sk_abe_for_(", "").rstrip(")")
            
            key_attrs_set = set()
            try:
                import ast
                # key_attrs_str_list_format should be like "['student_id:STU-2', 'degree_topic:B.S. Computer Science']"
                parsed_attributes = ast.literal_eval(key_attrs_str_list_format)
                if isinstance(parsed_attributes, list):
                    key_attrs_set = set(parsed_attributes) # This creates a set like {'student_id:STU-2', 'degree_topic:B.S. Computer Science'}
                else:
                    print(f"[ABE SIM] WARNING: Parsed key attributes is not a list: {parsed_attributes}. Using fallback parsing.")
                    # Fallback if not a list, though it should be based on key generation
                    key_attrs_set = set(attr.strip() for attr in key_attrs_str_list_format.replace("[","").replace("]","").replace("'","").split(","))
            except Exception as e_ast:
                print(f"[ABE SIM] Error parsing key attributes with ast.literal_eval: {e_ast}. Using fallback parsing.")
                # Fallback parsing if ast.literal_eval fails (e.g. if format is not a valid Python literal string)
                key_attrs_set = set(attr.strip() for attr in key_attrs_str_list_format.replace("[","").replace("]","").replace("'","").split(","))

            # Parse policy attributes from policy string (e.g., "student_id:STU-2,degree_topic:B.S. Computer Science")
            policy_attrs_set = set(attr.strip() for attr in policy_str.split(","))

            print(f"[ABE SIM] Key attributes after parsing: {key_attrs_set}")
            print(f"[ABE SIM] Policy attributes: {policy_attrs_set}")

            # Check if policy attributes are a subset of key attributes
            if policy_attrs_set.issubset(key_attrs_set):
                print(f"[ABE SIM] Policy {policy_attrs_set} satisfied by key attributes {key_attrs_set}. Decryption successful.")
                # Extract original data (very simplified)
                original_data = encrypted_content.replace(f"abe_encrypted_version_of(", "").replace(f")_under_policy({policy_str})", "")
                return original_data
            else:
                print(f"[ABE SIM] Policy {policy_attrs_set} NOT satisfied by key attributes {key_attrs_set}. Decryption failed.")
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

import random
import hashlib

class TSSSimulation:
    def __init__(self, num_participants, threshold):
        self.num_participants = num_participants
        self.threshold = threshold
        if threshold > num_participants:
            raise ValueError("Threshold cannot exceed the number of participants.")
        
        # Simulate each participant holding a share of a private key
        self.key_shares = {f"participant_{i+1}": random.randint(1000, 9999) for i in range(num_participants)}
        # Simulate a public key corresponding to the shared private key
        self.public_key = f"tss_pubkey_for_({num_participants}_of_{threshold})_scheme"
        print(f"[TSS SIM] Setup with {num_participants} participants, threshold {threshold}. Public Key: {self.public_key}")

    def generate_signature_share(self, participant_id, message_to_sign):
        """Simulates a participant generating a share of a threshold signature."""
        if participant_id not in self.key_shares:
            print(f"[TSS SIM] Error: Participant {participant_id} not found.")
            return None
        
        # In a real TSS, this would involve cryptographic operations with the key share and message.
        message_hash = hashlib.sha256(message_to_sign.encode()).hexdigest()
        signature_share = f"sig_share_from_({participant_id})_for_msg_hash({message_hash[:10]}...)_using_share({self.key_shares[participant_id]})"
        print(f"[TSS SIM] Participant {participant_id} generated signature share for message: {message_to_sign}")
        return signature_share

    def combine_signature_shares(self, signature_shares_list, message_to_sign):
        """Simulates combining enough signature shares to form a full threshold signature."""
        if len(signature_shares_list) < self.threshold:
            print(f"[TSS SIM] Error: Not enough signature shares ({len(signature_shares_list)}) to meet threshold ({self.threshold}).")
            return None
        
        # Verify all shares are for the same message
        message_hash = hashlib.sha256(message_to_sign.encode()).hexdigest()
        expected_hash_prefix = message_hash[:10]
        
        # Check each share is for the intended message
        for share in signature_shares_list:
            if f"_for_msg_hash({expected_hash_prefix}" not in share:
                print(f"[TSS SIM] Error: Share {share[:30]}... is not for the expected message.")
                return None
        
        print(f"[TSS SIM] Combining {len(signature_shares_list)} signature shares for message: {message_to_sign}")
        # In a real TSS, this involves Lagrange interpolation or similar techniques.
        # Here, we just confirm that enough shares were provided.
        full_signature = f"full_tss_signature_for_msg_hash({message_hash[:10]}...)_from_({len(signature_shares_list)})_shares"
        print(f"[TSS SIM] Full threshold signature generated: {full_signature}")
        return full_signature

    def verify_signature(self, full_signature, message_to_sign, public_key):
        """Simulates verifying a full threshold signature against the public key and message."""
        if public_key != self.public_key:
            print(f"[TSS SIM] Error: Verification failed. Public key mismatch.")
            return False
        
        message_hash = hashlib.sha256(message_to_sign.encode()).hexdigest()
        expected_signature_prefix = f"full_tss_signature_for_msg_hash({message_hash[:10]}...)"
        
        if full_signature and full_signature.startswith(expected_signature_prefix):
            print(f"[TSS SIM] Signature verification successful for message: {message_to_sign}")
            return True
        else:
            print(f"[TSS SIM] Signature verification failed for message: {message_to_sign}")
            return False

if __name__ == '__main__':
    # Example: 3 KAMC members, threshold of 2 needed to sign an approval
    kamc_tss_system = TSSSimulation(num_participants=3, threshold=2)
    print(f"KAMC TSS Public Key: {kamc_tss_system.public_key}")

    approval_message = "approve_abe_key_generation_for_STU-1_attributes_student_id:STU-1"
    reject_message = "reject_abe_key_generation_for_STU-1_attributes_student_id:STU-1"
    # Participants generate shares
    share1 = kamc_tss_system.generate_signature_share("participant_1", approval_message)
    share2 = kamc_tss_system.generate_signature_share("participant_2", approval_message)
    share3 = kamc_tss_system.generate_signature_share("participant_3", reject_message)

    if share1 and share2:
        kamc_approval_signature = kamc_tss_system.combine_signature_shares([share1, share2], approval_message)
        if kamc_approval_signature:
            print(f"KAMC Approval Signature: {kamc_approval_signature}")

            # Verify signature
            is_valid = kamc_tss_system.verify_signature(kamc_approval_signature, approval_message, kamc_tss_system.public_key)
            print(f"KAMC Approval Signature Valid: {is_valid}")
    
    # Test with insufficient shares
    if share1:
        failed_signature = kamc_tss_system.combine_signature_shares([share1], approval_message)
        print(f"Attempt with insufficient shares: {failed_signature}")


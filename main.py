from ecdh import make_keypair_pr_pb, point_multiplication
from elgamal import generate_keys, sign_message, verify_signature
from kuznyechik import unpad_message, pad_message, kuznyechik_decrypt, kuznyechik_encrypt

def main():
    # Prompt user for input and pad the message
    msg = input("Enter the message you want to encrypt: ")
    block_size = 16
    padded_msg = pad_message(msg, block_size)
    encrypted_msg = ""
    decrypted_msg = ""

    # Step 1: Elliptic Curve Diffie-Hellman key exchange to derive a shared secret
    print("Starting key exchange process to derive the shared secret key...")

    alice_secret_key, alice_public_key = make_keypair_pr_pb()
    bob_secret_key, bob_public_key = make_keypair_pr_pb()

    print("Alice's secret key:\t", alice_secret_key)
    print("Bob's secret key:\t", bob_secret_key)
    print("==========================")

    shared_secret1 = point_multiplication(bob_secret_key, alice_public_key)
    shared_secret2 = point_multiplication(alice_secret_key, bob_public_key)

    # Ensure both parties have the same shared secret
    print("Alice's shared key:\t", shared_secret1)
    print("Bob's shared key:\t", shared_secret2)
    print("==========================")
    print("The shared secret value/key is the x-value: \t", shared_secret1[0])

    # Step 2: Kuznyechik encryption using the shared secret
    print("==========================")
    print("Encrypting the message...")
    for idx in range(len(padded_msg) // block_size):
        msg_block = padded_msg[idx * block_size : idx * block_size + block_size]
        hexa_msg = msg_block.encode('utf-8').hex()
        PT = int(hexa_msg, 16)
        CT = kuznyechik_encrypt(PT, shared_secret1[0])
        encrypted_msg += bytes.fromhex(hex(CT)[2:]).decode('utf-8', errors='ignore')
        DT = kuznyechik_decrypt(CT, shared_secret1[0])
        decrypted_msg += bytes.fromhex(hex(DT)[2:]).decode('utf-8', errors='ignore')

    print("Encryption complete!")
    print("==========================")

    # Step 3: ElGamal Digital Signature
    print("Creating a digital signature using ElGamal...")

    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE65381FFFFFFFFFFFFFFFF", 16
    )
    g = 2

    elgamal_pub_k, elgamal_prv_k = generate_keys(p, g)
    signature = sign_message(elgamal_prv_k, p, g, encrypted_msg)
    print("Message signed!")
    print("==========================")
    print("Verifying the signature...")
    is_valid = verify_signature(elgamal_pub_k, encrypted_msg, signature)
    print("Signature valid:", is_valid)
    print("==========================")

    # Unpad the decrypted message
    decrypted_msg = unpad_message(decrypted_msg)

    # Display results
    print(f"Encrypted message: {encrypted_msg}")
    print(f"Decrypted message: {decrypted_msg}")
    print("==========================")
    print(f"Messages are equal: {msg == decrypted_msg}")

if __name__ == "__main__":
    main()

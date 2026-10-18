from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# In bytes
AES_BLOCKSIZE = 16

def xor(a: bytes, b: bytes) -> bytes:
    out = bytearray()
    for byteA, byteB in zip(a, b):
        out.append(byteA ^ byteB)
    return out

# AES electronic codebook mode (simplest)
def aes_ebc(key: bytes, plaintext: bytes, *, encrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    if encrypt:
        e = cipher.encryptor()
        return e.update(plaintext) + e.finalize()
    else:
        d = cipher.decryptor()
        return d.update(plaintext) + d.finalize()

# AES encrypt in CBC mode (randomized IV)
# Cryptography has AES in CBC mode, but here we implement ourselves
def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes | None) -> bytes:

    # Padding for CBC mode:
    # If plaintext len is not multiple of 16, append padding
    # of n for n bytes long. Otherwise, append dummy block 
    # of 16 for 16 bytes long. PKCS7 handles both cases.
    padder = padding.PKCS7(128).padder()
    in_padded: bytes = padder.update(plaintext) + padder.finalize()

    # Random IV (16 bytes)
    rand_IV: bytes = bytes()
    if iv is None:
        rand_IV = os.urandom(16)
    else:
        rand_IV = iv

    # Ciphertext: IV + c[0] + c[1] + ...
    ct_blocks: list[bytes] = []
    ct_blocks.append(rand_IV)

    # Chaining:
    # c[0] <- E(k, m[0] XOR IV)
    # c[i] <- E(k, m[i] XOR c[i-1]) : i ={1, 2, ..., last-block - 1}
    prev = rand_IV
    for byte_idx in range(0, len(in_padded), AES_BLOCKSIZE):
        c = aes_ebc(
            key,
            xor(in_padded[byte_idx: byte_idx + AES_BLOCKSIZE], prev),
            encrypt=True
        )
        ct_blocks.append(c)
        prev = c

    # Returns full ct, with IV prepended
    return b"".join(ct_blocks)

# AES decrypt in CBC mode (randomized IV)
# Ciphertext assumed to be padded!
def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:

    pt_blocks: list[bytes] = []

    # Decryption
    # m[0] <- D(k, c[0]) XOR IV : IV is prepended to CT
    # m[i] <- D(k, c[i]) XOR c[i-1] : i = {1, ..., last-block - 1}
    for byte_idx in range(16, len(ciphertext), AES_BLOCKSIZE):
        ct_prev_blk = ciphertext[byte_idx - AES_BLOCKSIZE: byte_idx]
        ct_curr_blk = ciphertext[byte_idx: byte_idx + AES_BLOCKSIZE]
        m = xor(
            aes_ebc(key, ct_curr_blk, encrypt=False),
            ct_prev_blk,
        )
        pt_blocks.append(m)

    ## Unpad to return message. Use PKCS7
    pt_padded = b"".join(pt_blocks)
    unpadder = padding.PKCS7(128).unpadder()
    out_pt = unpadder.update(pt_padded) + unpadder.finalize()

    # Return IV for testing encryption
    rand_iv: bytes = ciphertext[0: AES_BLOCKSIZE]

    return (out_pt, rand_iv)

# AES encrypt in CTR mode (randomized IV)
# Cryptography also has AES in CTR mode, but we implement ourselves.
def aes_ctr_encrypt(key: bytes, plaintext: bytes, iv: bytes | None) -> bytes:
    
    # Random IV (16 bytes)
    rand_IV: bytes = bytes()
    if iv is None:
        rand_IV = os.urandom(16)
    else:
        rand_IV = iv
    rand_IV_int: int = int.from_bytes(rand_IV, "big")

    # Ciphertext: IV + c[0] + c[1] + ...
    ct_blocks: list[bytes] = []
    ct_blocks.append(rand_IV)

    # Encryption:
    # Each pt block is XORed with AES encryption of key
    # and incrementing IV
    # c[i] <- m[i] XOR E(k, IV + i) : i = {0, 1, ..., last-block - 1}
    for iv_incr_count, byte_idx in enumerate(range(0, len(plaintext), AES_BLOCKSIZE)):
        # Safe incr of IV (max = 16 bytes (2^128 bits))
        counter: int = (rand_IV_int + iv_incr_count) % (1 << 128)
        # Pad = E(k, IV + i)
        pad: bytes = aes_ebc(
            key,
            counter.to_bytes(16, "big"),
            encrypt=True
        )
        c = xor(plaintext[byte_idx: byte_idx + AES_BLOCKSIZE], pad)
        ct_blocks.append(c)

    # Return as full ct, with IV prepended
    return b"".join(ct_blocks)

# AES decrypt in CTR mode (randomized IV)
def aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:

    pt_blocks: list[bytes] = []

    # Slice prepended IV from ct
    prepended_IV: bytes = ciphertext[0: AES_BLOCKSIZE]
    iv_int: int = int.from_bytes(prepended_IV, "big")

    # Actual ciphertext starts from byte 16
    ct_actual = ciphertext[AES_BLOCKSIZE:]
    
    # Decryption (in CTR mode we treat PRP as a PRF!)
    # Each ct block is XORed with AES ENCRYPTION of key
    # and incrementing IV (same direction as aes_ctr_encrypt)
    # m[i] <- c[i] XOR E(k, IV + i) : i = {0, 1, ..., last-block - 1}
    for iv_incr_count, byte_idx in enumerate(range(0, len(ct_actual), AES_BLOCKSIZE)):
        # Safe incr of IV (max = 16 bytes (2^128 bits))
        counter: int = (iv_int + iv_incr_count) % (1 << 128)
        # Pad = E(k, IV + i)
        pad = aes_ebc(
            key,
            counter.to_bytes(16, "big"),
            encrypt=True
        )
        m = xor(ct_actual[byte_idx: byte_idx + AES_BLOCKSIZE], pad)
        pt_blocks.append(m)

    return (b"".join(pt_blocks), prepended_IV)
    
def main():
    cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")

    print("Q1: CBC decryption")
    q1_cbc_ct: bytes = bytes.fromhex("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    q1_cbc_out: tuple[bytes, bytes] = aes_cbc_decrypt(cbc_key, q1_cbc_ct)
    q1_cbc_pt, q1_cbc_randIV = q1_cbc_out
    print(f"Plaintext (bytes): {q1_cbc_pt} \n")

    print("Q2: CBC decryption")
    q2_cbc_ct: bytes = bytes.fromhex("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")
    q2_cbc_out: tuple[bytes, bytes] = aes_cbc_decrypt(cbc_key, q2_cbc_ct)
    q2_cbc_pt, q2_cbc_randIV = q2_cbc_out
    print(f"Plaintext (bytes): {q2_cbc_pt} \n")

    print("Q3: CTR decryption")
    q3_ctr_ct: bytes = bytes.fromhex("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    q3_ctr_out: tuple[bytes, bytes] = aes_ctr_decrypt(ctr_key, q3_ctr_ct)
    q3_ctr_pt, q3_ctr_randIV = q3_ctr_out
    print(f"Plaintext (bytes): {q3_ctr_pt} \n")

    print("Q4: CTR decryption")
    q4_ctr_ct: bytes = bytes.fromhex("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")
    q4_ctr_out: tuple[bytes, bytes] = aes_ctr_decrypt(ctr_key, q4_ctr_ct)
    q4_ctr_pt, q4_ctr_randIV = q4_ctr_out
    print(f"Plaintext (bytes): {q4_ctr_pt} \n")

    print("Testing AES CBC and CTR encryptions...")
    assert aes_cbc_encrypt(cbc_key, q1_cbc_pt, q1_cbc_randIV) == q1_cbc_ct, "Q1 AES CBC Encryption failed"
    assert aes_cbc_encrypt(cbc_key, q2_cbc_pt, q2_cbc_randIV) == q2_cbc_ct, "Q2 AES CBC Encryption failed"
    assert aes_ctr_encrypt(ctr_key, q3_ctr_pt, q3_ctr_randIV) == q3_ctr_ct, "Q3 AES CTR Encryption failed"
    assert aes_ctr_encrypt(ctr_key, q4_ctr_pt, q4_ctr_randIV) == q4_ctr_ct, "Q4 AES CTR Encryption failed"
    print("Passed")

if __name__ == "__main__":
    main()
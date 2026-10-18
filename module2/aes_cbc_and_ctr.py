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
    cipher = Cipher(algorithms.AES(key), modes.ECB)
    if encrypt:
        e = cipher.encryptor()
        return e.update(plaintext) + e.finalize()
    else:
        d = cipher.decryptor()
        return d.update(plaintext) + d.finalize()

# AES encrypt in CBC mode (randomized IV)
# Cryptography has AES in CBC mode, but here we implement ourselves
def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:

    # Padding for CBC mode:
    # If plaintext len is not multiple of 16, append padding
    # of n for n bytes long. Otherwise, append dummy block 
    # of 16 for 16 bytes long. PKCS7 handles both cases.
    padder = padding.PKCS7(128).padder()
    in_padded: bytes = padder.update(plaintext) + padder.finalize()

    # Random IV (16 bytes)
    rand_IV: bytes = os.urandom(16)

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
def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:

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

    return out_pt

# AES encrypt in CTR mode (randomized IV)
# Cryptography also has AES in CTR mode, but we implement ourselves.
def aes_ctr_encrypt(key: bytes, plaintext: bytes) -> bytes:
    
    # Random IV (16 bytes)
    rand_IV: bytes = os.urandom(16)
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
            counter.to_bytes(),
            encrypt=True
        )
        c = xor(plaintext[byte_idx: byte_idx + AES_BLOCKSIZE], pad)
        ct_blocks.append(c)

    # Return as full ct, with IV prepended
    return b"".join(ct_blocks)

# AES decrypt in CTR mode (randomized IV)
def aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:

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
            counter.to_bytes(),
            encrypt=True
        )
        m = xor(ct_actual[byte_idx: byte_idx + AES_BLOCKSIZE], pad)
        pt_blocks.append(m)

    return b"".join(pt_blocks)


# def test_aes_cbc():

# def test_aes_ctr():
    
def main():
    return


if __name__ == "__main__":
    main()
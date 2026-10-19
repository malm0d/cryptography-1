original_text = b'Pay Bob 100$'
target_text = b'Pay Bob 500$'
print(len(original_text)) # 12 bytes
print(len(target_text)) # 12 bytes

c_hex = "20814804c1767293b99f1d9cab3bc3e7ac1e37bfb15599e5f40eef805488281d"
c_bytes = bytes.fromhex(c_hex)

# m = D(k, c) XOR IV
# m' = D(k, c) XOR IV XOR "Pay Bob 100" XOR "Pay Bob 500"
# m' = D(k, c) XOR (IV XOR "Pay Bob 100" XOR "Pay Bob 500")
#    = m XOR "Pay Bob 100" XOR "Pay Bob 500"
#    = "Pay Bob 500"

IV = c_bytes[0:16] # 16 bytes
c_zero = c_bytes[16:] # 16 bytes (this is padded)

pad = bytes([4] * 4) # pad of 4 bytes (PKCS7)

m_bytes = original_text + pad
target_bytes = target_text + pad

assert len(IV) == len(m_bytes) == len(target_bytes)

# #IV' = IV XOR "Pay Bob 100" XOR "Pay Bob 500"
IV_prime = bytearray()
for a, b, c in zip(IV, m_bytes, target_bytes):
    IV_prime.append(a ^ b ^ c)

c_prime = IV_prime + c_zero
assert len(c_prime) == 32

print(c_prime.hex())
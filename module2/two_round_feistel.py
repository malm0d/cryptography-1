# Array: [
#   ("L2_of_0^(64) R2_of_0^(64)", "L2_of_1^(32)0^(32) R2_of_1^(32)0^(32)"),
#   ...
# ]
# All 64-bit outputs are encoded as 16 hex chars; L, R, are 32 bits each.
# L2 and R2 make a 64 bit output of a two round Feistel.
candidate_output_pairs = [
    ("e86d2de2 e1387ae9", "1792d21d b645c008"),
    ("5f67abaf 5210722b", "bbe033c0 0bc9330e"),
    ("7c2822eb fdc48bfb", "325032a9 c5e2364b"),
    ("7b50baab 07640c3d", "ac343a22 cea46d60")
]

# Writing each (L2, R2) in terms of L0, R0 and round functions F(k1, .) & F(k2, .),
# we established that,
# - For F_2(., 0^(64)), the ciphertext L2 || R2 is equiv to:
#       F(k1, 0^(32)) || F(k2, F(k1, 0^(32)))
# - For F_2(., 1^(32)0^(32)), the ciphertext L2 || R2 is equiv to:
#       (1^(32) XOR F(k1, 0^(32))) || F(k2, 1^(32) XOR F(k1, 0^(32)))
#
# Then if we perform L2 of F_2(., 0^64) XOR L2 of F_2(., 1^(32)0^(32)),
# we should be getting 1^32 since the keys cancel out.
# The XOR of both R_2 components will just return giberish.

for i, output_pair in enumerate(candidate_output_pairs):
    L2_64, R2_64 = output_pair[0].split()
    L2_32_32, R2_32_32 = output_pair[1].split()
    
    # cast hexadecimal string (base 16) to integer,
    # then XOR operands
    L2_XOR = int(L2_64, 16) ^ int(L2_32_32, 16)
    R2_XOR = int(R2_64, 16) ^ int(R2_32_32, 16)
    
    # print as hexadecimal, look for "ffffffff" -> 1^(32)
    print(f"Pair {i}: {output_pair}")
    print(f"Left XOR = {L2_XOR:08x}    Right XOR = {R2_XOR:08x} \n")
    
    
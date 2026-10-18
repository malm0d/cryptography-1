import sys, string

# Key ideas:
# Since k is used in E(k, m) for all m, then we have that:
# - c1 XOR c2 = (k XOR m1) XOR (k XOR m2) = m1 XOR m2
# - 'A' to 'Z' are 0x41 - 0x5A
# - 'a' to 'z' are 0x61 - 0x7A
# - Space ' ' is 0x20.
#
# - 'a' XOR ' ' = 'A' (flip)
# - 'A' XOR ' ' = 'a' (flip)
# - 'a' XOR 'A' = ' ' (space)
# - 'a' XOR 'a' = 0 (null. XOR of self yields 0)
# - ' ' XOR ' ' = 0 (null)
# - 'a' XOR 'b' = (same case) not printable
# - 'A' XOR 'B' = (same case) not printable
# - 'a' XOR 'B' = within printable
# - 'A' XOR 'b' = within printable
#
# Notably:
# For each byte stream:
#   - If the XOR yields an alphabet, one operand is an alphabet and
#     the other operand is a space " ".
# 
#   - If the XOR yields a space " ", operands are the same character,
#     but different case, e.g. 'a' XOR "A". 
#
#   - If the XOR yields 0, the operands are same.
#
#   - Focus on what is printable and potential spaces. The range for 
#     printables (incl space) is 0x20–0x7e (32-126 in decimal).
#     (Check string.printable).
#
#   - The XOR of two ciphertexts is the same as XOR of two messages
#     since the keys cancel out.
#
# Perform c[i] XOR c[j] (which is equiv to m[i] XOR m[j]).
# Do c_i XOR c_j for j in {0, ... n-1} where j != i, so we measure,
# for each byte pos in c_i against all c_j, did the XOR yield an
# alphabet/printable char.
#
# Tally those scores. Each byte pos should not exceed 10 since for each
# c_i we only XOR-ing with 10 c_j. If the score at the pos is more than
# a set threshold, then we can say that c_i is likely a space " " at
# that pos in the original message m_i.
# 
# Recover key bytes up to length of the target ciphertext, 
# so that we can take: k XOR cTarget = mTarget.
# To construct the key, we need to take c XOR m.

ciphertextsHex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

TARGETCIPHERTEXTINDEX = -1

# Threshold to exceed to likely be considered a space " ".
# Total possible outcomes: 10.
COUNT_THRESHOLD = 7

ciphertextsBytes = [bytes.fromhex(c) for c in ciphertextsHex]

def hexToBytestream(h):
    return bytes.fromhex(h)

def bytestreamToHex(b):
    return b.hex()

def findLongest(arr):
    longest = 0
    for i in arr:
        if len(i) > longest:
            longest = len(i)
    return longest

# Given two byte streams, zip handles truncation,
# i.e. stops at shorter of two.
def xor(bytesA, bytesB) -> bytearray:
    res = bytearray()
    for x, y in zip(bytesA, bytesB) :
        res.append(x ^ y)
    return res

# Takes an array of n ciphertexts (from the same key).
# For each ciphertext, XOR pairwise with every other ciphertext,
# i.e: c_i XOR c_j for j in {0, ... n-1} where j != i.
#
# Tallies, for every byte pos of the result from the XOR operation of
# c_i with all c_j, how many returned a alphabet/printable char.
# (Returning alpha/printable char counts as a XOR hit).
#
# When c_i XOR c_j returns an alpha/printable char at the byte pos,
# it indicates a potential space " " (0x20) in either ciphertexts
# of the origitnal messages.
def countXorHitsInBytePos(ctArr: list[bytes]) -> dict[int, list[int]]:
    
    # { c_i: [byte pos tally] }
    res: dict[int, list[int]] = {}

    for i, ciphertext_i in enumerate(ctArr):

        # Init with array of `0` as starting count for each byte pos
        res[i] = [0] * len(ciphertext_i)

        for j, ciphertext_j in enumerate(ctArr):

            # Skip if i == j
            if i == j:
                continue
            
            xorBytestream = xor(ciphertext_i, ciphertext_j)

            # Check if byte is an alpha/printable char
            for pos, byte in enumerate(xorBytestream):
                char = chr(byte)
                if char.isalpha() and (char in string.printable):
                    res[i][pos] += 1

    return res

# Takes a map representing each ciphertext's alpha/printable hits in each
# byte position (from XOR-ing).
#
# For each ciphertext and the number of alpha/printable hits in each of its 
# byte positions, mark that position as `True` in the corresponding index of
# an output array.
#
# When an index in the corresponding output array is marked `True`, it signals
# that the number of hits exceeded a set threshold, such that the corresponding
# byte position in the ciphertext is likely a space " " in the original message, 
# since the XOR with every other ciphertext returned an alpha/printable char for 
# that byte pos for enough times.
def weighXorHits(x: dict[int, list[int]]) -> dict[int, list[bool]]:
    
    # out := { c_i : [is " " ? 1 : 0] }
    out: dict[int, list[bool]] = {}

    for i, xorHits in x.items():    

        # Init with array of `False` for each position
        out[i] = [False] * len(xorHits)

        # If position has hits more than the threshold,
        # mark position as True
        for pos, posCount in enumerate(xorHits):
            if posCount >= COUNT_THRESHOLD:
                out[i][pos] = True

    return out

# Takes a bytes array of ciphertexts
#
# For each ciphertext, XOR with 0x20 in every byte position.
#
# Since c := m ^ k, then k := m ^ c.
# If byte pos in m is a space " ", then XOR-ing with c yields the
# actual key value in that byte pos.
def xorCtWith0x20(ctArr: list[bytes]) -> dict[int, bytes]:
    
    # out := { c_i, bytestream from XOR-ing }
    out: dict[int, bytes] = {}

    for i, ctBytestream in enumerate(ctArr):
        spacesBytestream = bytes([0x20] * len(ctBytestream))
        xorRes = xor(ctBytestream, spacesBytestream)
        out[i] = xorRes

    return out

def recoverPatchyKey(
    ctKnownSpacePosns: dict[int, list[int]],
    ctXorSpace: dict[int, bytes]
) -> dict[int, bytes]:

    # Init a list to hold each byte value of the key.
    # Posns that are not known to be spaces are `None`, while posns
    # that are known spaces should contain the value of ctXorSpace
    # at that position.
    # Type: `bytes` is immutable, `byte` == `int` in Python
    patchyKey: list[int | None] = [None] * len(ciphertextsBytes[TARGETCIPHERTEXTINDEX])

    # We expect known spaces to be something like:
    # c_0: [T, F, F, F, F, T, F, ... ]
    # c_1: [F, F, T, T, F, T, F, ... ]
    # c_2: [F, F, F, F, T, F, T, ... ]
    # And if at any pos the "matrix" yields `True`, we copy into that 
    # pos of the key array the value of ctXorSpace of c_i at the same pos.
    # If two c_i yield `True` for space at the same pos, it is not an issue 
    # since all ciphertexts were constructed with the same key, and so the
    # value of ctXorSpace at that pos for two c_i should be the same since
    # it points to the same key.
    for c_i in ctKnownSpacePosns:
        c_iSpacePosns = ctKnownSpacePosns[c_i]

        for pos, isLikelySpace in enumerate(c_iSpacePosns):

            if pos > len(ciphertextsBytes[TARGETCIPHERTEXTINDEX]) - 1:
                break

            if isLikelySpace:
                patchyKey[pos] = ctXorSpace[c_i][pos]
    
    return patchyKey

def main():

    xorTallyPerCipherTxt = countXorHitsInBytePos(ciphertextsBytes)

    # Byte positions likely to be spaces
    potential0x20Posns = weighXorHits(xorTallyPerCipherTxt)

    ctXorWithSpace = xorCtWith0x20(ciphertextsBytes)

    patchyKey = recoverPatchyKey(potential0x20Posns, ctXorWithSpace)
    
    message = ""

    for i in range(len(patchyKey)):
        if patchyKey[i] != None:
            char = chr(patchyKey[i] ^ ciphertextsBytes[-1][i])
            message += char
        else:
            message += "*"

    print(message)
        
if __name__ == "__main__":
    main()
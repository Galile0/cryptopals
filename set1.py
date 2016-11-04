import itertools

from api.set1 import *
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode

def c1():
    challenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert(b64encode(unhexlify(challenge)).decode('ascii') == result)
    return unhexlify(challenge).decode('ascii')


def c2():
    challenge = ["1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"]
    result = "746865206b696420646f6e277420706c6179"
    assert(fixed_xor(challenge[0], challenge[1], True).decode('ascii') == result)
    return unhexlify(result).decode('ascii')


def c3(challenge="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", is_ascii=True):
    results = sb_xor(challenge, is_ascii)
    solutions = {}
    for result in results:
        result_str = unhexlify(result).decode('ascii')
        score = score_english(result_str)
        if score:
            solutions[result_str] = score
    return solutions


def c4():
    challenges = [line.rstrip('\n') for line in open('c4.txt')]
    solutions = {}
    for challenge in challenges:
        sol = c3(challenge)
        if sol:
            solutions.update(sol)
    return solutions


def c5():
    data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    result = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a"\
             "282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    key = "ICE"
    plain = hexlify(bytes(data, 'utf-8')).decode('ascii')
    ext_key = (hexlify(bytes(key, 'utf-8')) * len(plain))[:len(plain)].decode('ascii')
    solution = fixed_xor(ext_key, plain, False)
    assert(len(solution) == len(result)), "C5 Length mismatch"
    assert(solution.decode('ascii') == result), "C5 data mismatch"
    return data


def c6():
    h1 = bytes("this is a test", "utf-8")
    h2 = bytes("wokka wokka!!!", "utf-8")
    assert(hamming_distance(h1, h2) == 37)
    keysize_max = 40
    file = b64decode(''.join([line.rstrip('\n') for line in open('c6.txt')]))

    #  Step 1: Simplified CI to guess key-length
    keysize_prob = {}
    for k in range(2, keysize_max):
        distance_norm = hamming_distance(file[:k], file[k:k*2]) / k
        keysize_prob[k] = distance_norm
    keysizes = [x[0] for x in sorted(keysize_prob.items(), key=itemgetter(1))][:5]
    #  Step 2: Find Key with highest ascii-score
    keys = {}
    keysizes = [29]
    for k in keysizes:
        blocks = [file[i:i+k] for i in range(0, len(file), k)]
        tblocks = list(itertools.zip_longest(*blocks, fillvalue=0))
        key = []
        keyscore = 0
        for tblock in tblocks:
            tblock_hex = ''.join([hex(x)[2:].zfill(2) for x in tblock])
            plaintexts = sb_xor(tblock_hex, True)
            highscore = 0
            key_byte = 0
            for i, plaintext in enumerate(plaintexts):
                score = score_letter(unhexlify(plaintext).decode('ascii'))
                if score > highscore:
                    highscore = score
                    key_byte = i
            key.append(key_byte)
            keyscore += highscore
        keyscore /= len(key)
        keys[keyscore] = key

    #  Step 3: Decrypt with key with the highest ascii score
    key = sorted(keys.items(), key=itemgetter(0), reverse=True)[0]
    ext_key = key[1] * 64
    decrypt = bxor(ext_key, file[:len(ext_key)], False)
    return ''.join([chr(x) for x in key[1]]), decrypt

if __name__ == "__main__":
    print("Challenge 1:", c1())
    print("Challenge 2:", c2())
    print("Challenge 3:", c3())
    print("Challenge 4:", c4())
    print("Challenge 5:", c5())
    print("Challenge 6:", c6()[0])


"""
import base64
import challenge3
import challenge5
import itertools

def getHammingDistance(x, y):
    return sum([bin(x[i] ^ y[i]).count('1') for i in range(len(x))])

x = b'this is a test'
y = b'wokka wokka!!!'
expectedD = 37
d = getHammingDistance(x, y)
if d != expectedD:
    raise Exception(encodedD + ' != ' + encodedExpectedD)

x = base64.b64decode(open('6.txt', 'r').read())

def breakRepeatingKeyXor(x, k):
    blocks = [x[i:i+k] for i in range(0, len(x), k)]
    transposedBlocks = list(itertools.zip_longest(*blocks, fillvalue=0))
    key = [challenge3.breakSingleByteXOR(bytes(x))[0] for x in transposedBlocks]
    return bytes(key)

def normalizedEditDistance(x, k):
    blocks = [x[i:i+k] for i in range(0, len(x), k)][0:4]
    pairs = list(itertools.combinations(blocks, 2))
    scores = [getHammingDistance(p[0], p[1])/float(k) for p in pairs][0:6]
    return sum(scores) / len(scores)

k = min(range(2, 41), key=lambda k: normalizedEditDistance(x, k))

key = breakRepeatingKeyXor(x, k)
y = challenge5.encodeRepeatingKeyXor(x, key)
print(key, y)
"""
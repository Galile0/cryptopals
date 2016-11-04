from api.common import *
from binascii import hexlify, unhexlify
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

def c1():
    challenge = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert(b64encode(unhexlify(challenge)).decode('ascii') == result), "C1 Data Mismatch"
    return unhexlify(challenge).decode('ascii')


def c2():
    challenge = ["1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"]
    result = unhexlify("746865206b696420646f6e277420706c6179")
    assert(xor_bytes(unhexlify(challenge[0]), unhexlify(challenge[1])) == result), "C2 Data Mismatch"
    return result.decode('ascii')


def c3(challenge="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"):
    results = break_sb_xor(unhexlify(challenge), PRINTABLE)
    solutions = {}
    for result in results.values():
        result_str = result.decode('ascii')
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
    plain = bytes(data, 'utf-8')
    ext_key = (bytes(key, 'utf-8') * len(plain))[:len(plain)]
    solution = hexlify(xor_bytes(ext_key, plain))
    assert(len(solution) == len(result)), "C5 Length mismatch"
    assert(solution.decode('ascii') == result), "C5 data mismatch"
    return data


def c6():
    h1 = bytes("this is a test", "utf-8")
    h2 = bytes("wokka wokka!!!", "utf-8")
    assert(hamming_distance(h1, h2) == 37)
    keysize_max = 40
    keysize_try = 5
    file = b64decode(''.join([line.rstrip('\n') for line in open('c6.txt')]))

    #  Step 1: Simplified IC to guess key-length //That shit needs improvements all over the place
    keysize_prob = {}
    for k in range(2, keysize_max):
        distance_norm = hamming_distance(file[:k], file[k:k*2]) / k
        keysize_prob[k] = distance_norm
    keysizes = [k for k in sorted(keysize_prob, key=keysize_prob.get)][:keysize_try]

    #  Step 2: Find Key with highest ascii-score
    found_keys = {}
    keysizes.extend([27, 28, 29, 30])
    for k in keysizes:
        blocks = [file[i::k] for i in range(k)]
        key = bytearray()
        keyscore = 0
        for block in blocks:
            plain = break_sb_xor(block, PRINTABLE)
            if not plain:  # No key gave any ascii Output
                break
            highscore = 0
            key_byte = 0
            for kb, v in plain.items():
                score = score_letter(v.decode('ascii'))
                if score > highscore:
                    highscore = score
                    key_byte = kb
            key.append(key_byte)
            keyscore += highscore
        if key:
            keyscore /= len(key)
            found_keys[keyscore] = key

    #  Step 3: Decrypt with key with the highest ascii score
    key = sorted(found_keys.items(), key=lambda x: x[0], reverse=True)[0]
    ext_key = key[1] * (len(file) // len(key[1]))
    decrypt = xor_bytes(ext_key, file[:len(ext_key)])
    return ''.join([chr(x) for x in key[1]]), decrypt


def c7():
    file = b64decode(''.join([line.rstrip('\n') for line in open('c7.txt')]))

    key = b'YELLOW SUBMARINE'
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(file)
    return plaintext

if __name__ == "__main__":
    print("Challenge 1:", c1())
    print("Challenge 2:", c2())
    print("Challenge 3:", c3())
    print("Challenge 4:", c4())
    print("Challenge 5:", c5())
    print("Challenge 6:", c6())
    print("Challenge 7:", c7())

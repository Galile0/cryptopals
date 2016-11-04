char_distribution = {
                    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
                    'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
                    'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
                    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
                    'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
                    'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
                    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

common_words = [
                "the", "be", "to", "of", "and", "a", "in", "that", "have", "I", "it", "for", "not", "on", "with", "he",
                "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or",
                "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "out", "if", "about",
                "who", "get", "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him", "know",
                "take", "people", "into", "year", "your", "good", "some", "could", "them", "see", "other", "than",
                "then", "now", "look", "only", "come", "its", "over", "think", "also", "back", "after", "use", "two",
                "how", "our", "work", "first", "well", "way", "even", "new", "want", "because", "any", "these", "give",
                "day", "most", "us"
]

PRINTABLE = list(range(32, 127))
PRINTABLE.extend([9, 10, 13])
ASCII = list(range(127))


def xor_bytes(b1, b2, expected=None):
    """
    Performs bytewise XOR of two bytelike Operands b1, b2. If the ascii Flag is set, every Outputbyte is checked if
    it is <127. If not, the whole operation is aborted. This is to speed up the Computation significantly.
    :param b1: Bytelike Object
    :param b2: Bytelike Object
    :param expected: Optional list with expected bytes. Abort if outcome does not match
    :return: Result of b1 XOR b2 as bytes(). If is_ascii is set and the result contains bytes >127, return None
    """
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
        if expected and result[i] not in expected:
            return None
    return bytes(result)


def break_sb_xor(s, expected=None):
    """
    Bruteforces XOR encryption with a single byte key for arbitrary ciphertext lengths. Returns a dict of all keys with
    valid Output and the dycrpted bytes as values
    :param s: Bytelike Object
    :param expected: Optional list with expected bytes. Abort if outcome does not match
    :return: Dict {Key:Plaintext}
    """
    plaintexts = {}
    for i in range(255):
        key = [i] * len(s)
        plain = xor_bytes(key, s, expected)
        if plain:
            plaintexts[i] = plain
    return plaintexts


def score_english(data):
    words = data.split(" ")
    score = 0
    if words:
        for word in words:
            if word in common_words:
                score += 1
    return score


def score_letter(data):
    score = 0
    for c in data:
        try:
            if c.lower() in char_distribution:
                score += char_distribution[c.lower()]
        except AttributeError:
            pass
    return score


def score_printable(data):
    score = 0
    for c in data:
        if 32 < ord(c) < 127:
            score += 1
    return score


def hamming_distance(x, y):
    return sum([bin(x[i] ^ y[i]).count('1') for i in range(len(x))])

import unidecode
import string
import re
import math

from collections import Counter

def normalize(text):
    """
    Replace any special french character with it's "simpler" version and uppercase the text
    e.g. é => E

    Parameters
    ----------
    text: the plaintext to normalize

    Returns
    -------
    the normalized version of <text>
    """

    return ''.join(filter(str.isalpha, unidecode.unidecode(text).upper()))

def shift(char, key):
    """
    Shifts a char <char> by <key> times
    e.g. 
    char = 'A'
    key = 2
    shifted_char = 'C'

    Parameters
    ----------
    char: the char to shift
    key: the shift which is a number

    Returns
    -------
    the shifted char
    """ 
    alph = string.ascii_uppercase

    # quick check to see if it's in the alphabet
    # if not just return it
    if not char in alph:
        return char

    return alph[(alph.index(char)+key)%26]

def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number
    
    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    ciphertext = ""
    text = normalize(text)

    for char in text:
        ciphertext += shift(char, key)

    return ciphertext

def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number
    
    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """
    # to decrypt a Caeser cipher, we can simply use the encrypt with the negative version of the key
    return caesar_encrypt(text, -key)

def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse
    
    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text. 
    """
    freq_vector = [0] * 26
    
    text = normalize(text)

    occurences = Counter(text)

    alph = string.ascii_uppercase
    for key in occurences:
        if key in alph:
            freq_vector[alph.index(key)] = occurences[key]/sum(occurences.values())

    return freq_vector


def caesar_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break
    
    Returns
    -------
    a number corresponding to the caesar key
    """
    with open("sample/book.txt", "r") as f: 
        freq = freq_analysis(f.read())

    text = normalize(text)

    possible_key = 0
    lowest_estimate = -1
    for i in range(0,26):
        estimate = 0

        text_to_test = caesar_decrypt(text, i)
        occurences = Counter(text_to_test)

        for key in occurences:
            index = ord(key)-ord('A')
            estimate += ((occurences[key] - freq[index])**2) / freq[index]

        if lowest_estimate > estimate or lowest_estimate == -1:
            lowest_estimate = estimate
            possible_key = i

    return possible_key



def vigenere_cypher(text, key, encrypt = True):
    """
    Implementation of Vigenere's cypher. 
    
    Note: Since the same code is used for encryption and decryption the only 
          difference beeing the direction in which the text is shifted (hence <encrypted>)

    Parameters
    ----------
    text: the text to encrypt/decrypt
    key: the keyword used in Vigenere (e.g. "pass")
    encrypt: boolean to tell if we are encrypthing or not (default = True)
    
    Returns
    -------
    the value of <text> encrypted/decrypted with Vigenere under key <key>
    """
    shift_direction = 1 if encrypt else -1
    alph = string.ascii_uppercase
    text = normalize(text)
    key = key.upper()

    output = ""

    key_i = 0
    for i in range(len(text)):
        if text[i] not in alph:
            output += text[i]
            continue

        shiftv = alph.index(key[key_i % len(key)])
        output += shift(text[i], shift_direction*shiftv)
        key_i += 1

    return output

def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")
    
    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    return vigenere_cypher(text, key)

def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")
    
    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    return vigenere_cypher(text, key, False)

def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse
    
    Returns
    -------
    the index of coincidence of the text
    """
    text = normalize(text)

    N = len(text)

    if N <= 1:
        return N

    freq = Counter(text)
    freq_sum = sum(freq[key] * (freq[key] - 1) for key in freq)

    return 26*freq_sum/(N * (N - 1))


def most_likely_key_length(text, l, ref_ic, extra_shift=0):
    """
    Determine the most likely key length for a given cyphertext

    Note: It's possible that a multiple of the key length is returned.
          e.g. if the original key is "ABC", the function might return 6.
          Because there's no way of telling that it's not "ABCABC".
          Since both key will encrypt and decrypt a text the same

    Parameters
    ----------
    text: the cyphertext to analyse
    l: the maximum key length we're willing to guess
    ref_ic: the index of coincidence that we should aim for
    extra_shift: the value of a possible extra_shift (default = 0)

    Returns
    -------
    the most likely key length of the cyphertext <text> or None is nothing was found
    """
    likely_key = ref_ic

    for key_len in range(2, l+1):

        chunks = []
        for i in range(key_len):
            chunk = ""
            for j in range(0, len(text[i:]), key_len):
                # get the current chars position in the alphabet
                m_pos = ord(text[i+j]) - ord("A")
                # calculate the potential casear shift that was applied
                casear_shift = int(j/key_len)*extra_shift
                # add the char to the chunk (w/ the potentiel shift removed)
                chunk += chr((m_pos - casear_shift)%26 + ord("A"))

            if chunk != " ":
                chunks.append(chunk)

        avg_ic = sum(coincidence_index(chunk) for chunk in chunks)/key_len

        # check if the current avg is close to the reference ic
        if abs(avg_ic-ref_ic) < likely_key and math.isclose(avg_ic, ref_ic, abs_tol = 0.3):
            likely_key = key_len

    return likely_key if likely_key != ref_ic else None

def most_likely_key(text, key_length, extra_shift=0):
    """
    Determine the most likely key for a given cyphertext

    Parameters
    ----------
    text: the cyphertext to analyse
    key_length: the length of the key
    extra_shift: the value of a possible extra_shift (default = 0)

    Returns
    -------
    the most likely key of the cyphertext <text>
    """
    key = ""
    for i in range(key_length):
        chunk = ""
        for j in range(0, len(text[i:]), key_length):
            m_pos = ord(text[i+j]) - ord("A")
            casear_shift = int(j/key_length)*extra_shift%26

            chunk += chr((m_pos - casear_shift)%26 + ord("A"))

        key += chr(ord('A')+caesar_break(chunk))

    return key

def vigenere_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break
    
    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    MAX_KEY_LEN_GUESS = 20
    # get the ref ic
    with open("sample/book.txt", "r") as f: 
        ref_ic = coincidence_index(f.read())

    # find the most likely key length
    key_len = most_likely_key_length(text, MAX_KEY_LEN_GUESS, ref_ic)

    # find the most likely key
    key = most_likely_key(text, key_len)

    # decrypt the text with
    return vigenere_decrypt(text, key)



def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use. 
    
    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = normalize(text)

    # split the text into chucks of <vigenere_key> length
    chunks = [text[i:i+len(vigenere_key)] for i in range(0, len(text), len(vigenere_key))]

    cyphertext = ""
    cypher_key = vigenere_key
    # encrypt the text chunk by chunk while encrypting the key_vigenere after each chunk encryption
    for chunk in chunks:
        cyphertext += vigenere_encrypt(chunk, cypher_key)

        # encrypt the key with caesar
        cypher_key = caesar_encrypt(cypher_key, caesar_key)

    return cyphertext

def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use. 
    
    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = normalize(text)

    # split the text into chucks of <vigenere_key> length
    chunks = [text[i:i+len(vigenere_key)] for i in range(0, len(text), len(vigenere_key))]

    cyphertext = ""

    cypher_key = vigenere_key
    # encrypt the text chunk by chunk while encrypting the key_vigenere after each chunk encryption
    for chunk in chunks:
        cyphertext += vigenere_decrypt(chunk, cypher_key)

        # encrypt the key with caesar
        cypher_key = caesar_encrypt(cypher_key, caesar_key)

    return cyphertext

def vigenere_caesar_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break
    
    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    with open("sample/book.txt", "r") as f:  
        ref_ic = coincidence_index(f.read())

    caesar_key = 0
    likely_key_len = ref_ic
    for ckey in range(26):
        possible_key_len = most_likely_key_length(text, 20, ref_ic, extra_shift=ckey)

        if possible_key_len:
            likely_key_len = possible_key_len
            caesar_key = ckey

    vigenere_key = most_likely_key(text, likely_key_len, caesar_key)

    return (vigenere_key, caesar_key)

def main():
    print("Welcome to the Vigenere breaking tool")
    
    key = "cryptii"
    og_plaintext = (
        "DOIT CHANGER DE LIEU DE RÉUNION, PASSANT DU PONT AU PASSAGE SOUTERRAIN "\
        "CAR ON PENSE QUE DES AGENTS ENNEMIS ONT ÉTÉ ASSIGNÉS "\
        "POUR SURVEILLER LE PONT HEURE DE RÉUNION INCHANGÉ XX"
    )

    # ct = caesar_encrypt(og_plaintext, 10)
    # print(caesar_decrypt(ct, caesar_break(ct)))
    # print("\n")

    cypher = vigenere_encrypt(og_plaintext, key)
    print(cypher)
    print()
    plaintext = vigenere_decrypt(cypher, key)
    print(normalize(og_plaintext))
    print(plaintext)
    print("\n")

    # with open("vigenere.txt", "r") as f: 
    #     cypher = f.read() 

    # print(vigenere_break(cypher))
    # print("\n")

    # ck = 2
    # cypher = vigenere_caesar_encrypt(og_plaintext, key, ck)
    # print(cypher)

    # plaintext = vigenere_caesar_decrypt(cypher, key, ck)
    # print(plaintext)

    # vk, ck = vigenere_caesar_break(cypher)
    # print(vigenere_caesar_decrypt(cypher, vk, ck))

if __name__ == "__main__":
    main()



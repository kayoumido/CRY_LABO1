# Author: Doran Kayoumi
# NOTE: Don't forget to install https://pypi.org/project/Unidecode/

import unidecode
import string
import re
import math

from collections import Counter

def normalize(text):
    """
    Replace any special french character with it's "simpler" version and uppercase the text

    Example
    -------
    La crypto c'est génial => LACRYPTOCESTGENIAL

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

    Example
    -------
    char = 'A'
    key = 2

    => 'C'

    Parameters
    ----------
    char: the char to shift
    key: the shift which is a number

    Returns
    -------
    the shifted char
    """ 
    alph = string.ascii_uppercase

    # quick check to see if <char> is in the alphabet
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


def vigenere_chunkify(text, chunk_nb, key_len, extra_shift=0):
    """
    Returns a chunk of a given text

    Example
    -------
    text = ABCDEFG
    key_len = 2

    The text can be split into 2 chunks
    ACEG & BDF

    Parameters
    ----------
    text: the text were to get chunk
    chunk_nb: the chunk we want to extract
    key_len: the length of the key that cyphered <text>
    extra_shift: the value of a possible extra_shift (default = 0)

    Returns
    -------
    the wanted chunk
    """
    chunk = ""
    for j in range(0, len(text[chunk_nb:]), key_len):
        # add the char to the chunk (w/ the removal of a potentiel shift)
        chunk += shift(text[chunk_nb+j], -(int(j/key_len)*extra_shift))

    return chunk

def vigenere_chunkify_list(text, key_len, extra_shift=0):
    """
    Transforms a text into a list of chunks

    Example
    -------
    text = ABCDEFG
    key_len = 2

    The text will be split into 2 chunks
    [ACEG, BDF]

    Parameters
    ----------
    text: the text we want to split into chunks
    key_len: the length of the key that cyphered <text>
    extra_shift: the value of a possible extra_shift (default = 0)

    Returns
    -------
    the list of chunk
    """
    chunks = []
    for i in range(key_len):
        chunk = vigenere_chunkify(text, i, key_len, extra_shift)

        if chunk != " ":
            chunks.append(chunk)
    
    return chunks

def vigenere_unchunkify(chunks):
    """
    merge a list of chunks into a string

    Example
    -------
    [ACEG, BDF] => ABCDEFG

    Parameters
    ----------
    chunks: the list of chunks we want to merge

    Returns
    -------
    the list of chunk merged
    """
    output = ""
    for i in range(len(chunks[0])):
        for chunk in chunks:
            if i < len(chunk):
                output += chunk[i]
    return output

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
    text = normalize(text)
    key = key.upper()

    chunks = vigenere_chunkify_list(text, len(key))
    caesared_chunks = []

    for i in range(len(key)):
        shiftv = string.ascii_uppercase.index(key[i])
        caesared_chunks.append(caesar_encrypt(chunks[i], shift_direction*shiftv))

    return vigenere_unchunkify(caesared_chunks)

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

    Note
    ----
    It's possible that a multiple of the key length is returned.
    e.g. If the original key is "ABC", the function might return 6.
         Because there's no way of telling that the key isn't "ABCABC".
         Since both keys will encrypt and decrypt the same

    Parameters
    ----------
    text: the cyphertext to analyse
    l: the maximum key length we're willing to guess
    ref_ic: the index of coincidence that we should aim for
    extra_shift: the value of a possible extra_shift (default = 0)

    Returns
    -------
    the most likely key length of the cyphertext <text> or None if nothing was found
    """
    likely_key = ref_ic

    for key_len in range(2, l+1):
        chunks = vigenere_chunkify_list(text, key_len, extra_shift)
        avg_ic = sum(coincidence_index(chunk) for chunk in chunks)/key_len

        # check if the current avg is close to the reference ic
        if abs(avg_ic-ref_ic) < likely_key and math.isclose(avg_ic, ref_ic, abs_tol = 0.3):
            likely_key = key_len

    return likely_key if likely_key != ref_ic else None

def most_likely_key(text, key_len, extra_shift=0):
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
    for i in range(key_len):
        key += chr(ord('A')+caesar_break(vigenere_chunkify(text, i, key_len, extra_shift)))

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

    print("Found key: {}".format(key))

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
    print("-------------------------------------")
    print()

    print("Caesar cypher")
    print("-------------")
    caesar_text = (
        "DOIT CHANGER DE LIEU DE RÉUNION, PASSANT DU PONT AU PASSAGE SOUTERRAIN "\
        "CAR ON PENSE QUE DES AGENTS ENNEMIS ONT ÉTÉ ASSIGNÉS "\
        "POUR SURVEILLER LE PONT HEURE DE RÉUNION INCHANGÉ XX"
    )
    caesar_key = 10
    print("Orignial plaintext: {}\nKey: {}".format(caesar_text, caesar_key))
    print()
    
    ct = caesar_encrypt(caesar_text, caesar_key)
    print("Encrypted text: {}".format(ct))
    print("Decrypted text: {}".format(caesar_decrypt(ct, caesar_key)))
    print()

    print("Breaking Caesar")
    print("---")
    print("Found key: {}".format(caesar_break(ct)))

    print("\n")

    print("Vigenere cypher")
    print("---------------")
    vigenere_text = "La crypto c'est génial"
    vigenere_key = "cryptii"
    print("Orignial plaintext: {}\nKey: {}".format(vigenere_text, vigenere_key))
    print()

    ct = vigenere_encrypt(vigenere_text, vigenere_key)
    print("Encrypted text: {}".format(ct))
    print("Decrypted text: {}".format(vigenere_decrypt(ct, vigenere_key)))
    print()

    print("Breaking Vigenere")
    print("---")
    with open("vigenere.txt", "r") as f: 
        cypher = f.read() 

    print("Text to break: {}".format(cypher))
    print("Plaintext text: {}".format(vigenere_break(cypher)))
    
    print("\n")

    print("Vigenere Caesar cypher")
    print("----------------------")
    vigenere_caesar_text = "On s'amuse toujours à l'heig-vd!"
    vigenere_caesar_vkey = "cryptii"
    vigenere_caesar_ckey = 10
    print("Orignial plaintext: {}\nVigenere key: {}\nCaesar key: {}".format(vigenere_caesar_text, vigenere_caesar_vkey, vigenere_caesar_ckey))
    print()

    ct = vigenere_caesar_encrypt(vigenere_caesar_text, vigenere_caesar_vkey, vigenere_caesar_ckey)
    print("Encrypted text: {}".format(ct))
    print("Decrypted text: {}".format(vigenere_caesar_decrypt(ct, vigenere_caesar_vkey, vigenere_caesar_ckey)))
    print()

    print("Breaking Vigenere Caesar")
    print("---")
    with open("vigenereAmeliore.txt", "r") as f: 
        cypher = f.read()

    print("Text to break: {}".format(cypher))
    vkey, ckey = vigenere_caesar_break(cypher)
    print("Vigenere key: {}".format(vkey))
    print("Caesar key: {}".format(ckey))
    print("Plaintext text: {}".format(vigenere_caesar_decrypt(cypher, vkey, ckey)))

if __name__ == "__main__":
    main()



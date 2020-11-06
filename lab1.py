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
    char = 'C'

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
    encrypted = ""
    # normalize the text to encrypt & uppercase it
    text = normalize(text)

    for char in text:
        encrypted += shift(char, key)

    return encrypted

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
    encrypt: boolean to tell if we are encrypthing or not
    
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

    freq = Counter(text)
    freq_sum = sum(freq[key] * (freq[key] - 1) for key in freq)

    return 26*freq_sum/(N * (N - 1))



def get_likely_key_length(text, l, ref_ic):
    """
    Determine the most likely key length for a given cyphertext

    Note: It's possible that a multiple of the key lenght is returned.
          If the original key is "ABC", there's now way of telling that
          it's not "ABCABC". Since both key will encrypt and decrypt a text
          identicaly
    Parameters
    ----------
    text: the cyphertext to analyse
    l: the maximum key length we're willing to guess
    
    Returns
    -------
    the most likely key length of the cyphertext <text>
    """
    likely_key_n_ic = (2, ref_ic)

    for length in range(2, l+1):

        chunks = []
        for i in range(length):
            chunk = ""
            for j in range(0, len(text[i:]), length):
                chunk += text[i+j]

            if chunk != " ":
                chunks.append(chunk)

        avg_ic = sum(coincidence_index(chunk) for chunk in chunks)/length
        diff = abs(avg_ic-ref_ic)

        # check if the current avg is close to the reference ic
        if diff < likely_key_n_ic[1]:
            likely_key_n_ic = (length, diff)

    return likely_key_n_ic[0]

def most_likely_key(text, key_length):   
    key = ""
    for i in range(key_length):
        chunk = ""
        for j in range(0, len(text[i:]), key_length):
            chunk += text[i+j]

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
    key_len = get_likely_key_length(text, MAX_KEY_LEN_GUESS, ref_ic)

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
    #TODO you can delete the next lines if needed
    vigenere_key = ""
    caesar_key = ''
    return (vigenere_key, caesar_key)

def main():
    print("Welcome to the Vigenere breaking tool")
    
    key = "maison"
    og_plaintext = (
        "DOIT CHANGER DE LIEU DE RÉUNION, PASSANT DU PONT AU PASSAGE SOUTERRAIN "\
        "CAR ON PENSE QUE DES AGENTS ENNEMIS ONT ÉTÉ ASSIGNÉS "\
        "POUR SURVEILLER LA PONT HEURE DE RÉUNION INCHANGÉ XX"
    )

    ct = caesar_encrypt(og_plaintext, 10)
    print(caesar_decrypt(ct, caesar_break(ct)))
    print("\n")

    cypher = vigenere_encrypt(og_plaintext, key)
    print(cypher)
    print()
    plaintext = vigenere_decrypt(cypher, key)
    print(plaintext)
    print("\n")

    with open("vigenere.txt", "r") as f: 
        cypher = f.read() 

    print(vigenere_break(cypher))
    print("\n")

    cypher = vigenere_caesar_encrypt(og_plaintext, key, 2)
    print(cypher)

    plaintext = vigenere_caesar_decrypt(cypher, key, 2)
    print(plaintext)


if __name__ == "__main__":
    main()



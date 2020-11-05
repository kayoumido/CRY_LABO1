import unidecode
import string
import re

from collections import Counter

def normalize(text):
    """
    Replace any spécial french character with it's "simpler" version and uppercase the text
    e.g. é => E

    Parameters
    ----------
    text: the plaintext to normalize

    Returns
    -------
    the normalized version of <text>
    """
    return unidecode.unidecode(text).upper()

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
    normalized_text = normalize(text)

    for char in normalized_text:
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
    
    normalized_text = normalize(text)
    occurences = Counter(normalized_text)

    for key in occurences:
        alph = string.ascii_uppercase
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
    f = open("sample/book.txt", "r")
    freq = freq_analysis(f.read())
    f.close()

    normalized_text = normalize(text)
    normalized_text = re.sub('\W+','', normalized_text)

    possible_key = 0
    lowest_estimate = -1
    for i in range(0,26):
        estimate = 0

        text_to_test = caesar_decrypt(normalized_text, i)
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
    i = 0
    for j in range(len(text)):
        """
        Note: A second index was added to parse the plaintext
              This was done, so when a space is encountered,
              we can skip to the next letter in the plaintext
              BUT stay where we are for the key!

              Another solution would have been to simply remove the spaces 
              from the plaintext.
              Code to do so:
              text = re.sub('\W+','', text)
        """

        # just to make sure we aren't out of bounds
        if i >= len(text): break

        if text[i] not in alph:
            output += text[i]
            i += 1

        shiftv = alph.index(key[j % len(key)])
        # time to shift some letters :D
        output += shift(text[i], shift_direction*shiftv)

        i += 1

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
    #TODO
    return 0


def vigenere_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break
    
    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    #TODO
    return ''


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
    #TODO
    return ""

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
    #TODO
    return ""

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

    # ct = caesar_encrypt("Ceci est un texte dans la langue de Molliere", 10)
    # print(caesar_decrypt(ct, caesar_break(ct)))
    key = "cryptii"
    cypher = vigenere_encrypt("Welcome to the Vigenere breaking tool", key)
    print(cypher)
    plaintext = vigenere_decrypt(cypher, key)
    print(plaintext)

if __name__ == "__main__":
    main()



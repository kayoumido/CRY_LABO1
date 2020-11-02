import unidecode
import string
import re

from collections import Counter

def normalize(text):
    """
    Replace any spécial french character with it's "simpler" version and uppercase the text
    e.g. é => e
    Parameters
    ----------
    text: the plaintext to normalize

    Returns
    -------
    the normalized version of <text>
    """
    return unidecode.unidecode(text).upper()

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
        alph = string.ascii_uppercase
        if char in alph:
            pos = alph.index(char)
            encrypted += alph[(pos+key)%26]
            pass
        else:
            encrypted += char
            pass

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
    # normalized_text = re.sub('\W+','', normalized_text)
    occurences = Counter(normalized_text)
    text_to_test = normalized_text
    print(occurences)

    possible_key = 0
    lowest_estimate = -1
    for i in range(0,25):
        estimate = 0

        text_to_test = caesar_decrypt(text_to_test, i)
        occurences = Counter(text_to_test)
        
        for key in occurences:
            if freq[i] == 0: continue
            estimate += ((occurences[key] - freq[i])**2) / freq[i]

        if lowest_estimate > estimate or lowest_estimate == -1:
            lowest_estimate = estimate
            possible_key = i

    return possible_key


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
    #TODO
    return ""

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
    #TODO
    return ""

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

    print(caesar_break(caesar_encrypt("Ceci est un texte dans la langue de Molliere", 13)))
    #TODO something

if __name__ == "__main__":
    main()



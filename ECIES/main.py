"""
ECIES PROJECT-Theresa Nguyen
MODES: Encryption and Decryption
METHOD:
Asymmetric and symmetric encryption and decryption.
"""

import sys, getopt, os, hashlib, Chacha_poly

from os import urandom
from ecc import string_to_int, int_to_string
from curves import SECP_256k1
from Chacha_poly import ChaCha_Poly_AEAD

infile = ""
outfile = ""

"""
Taken from ecc_toy.py
"""
### BEGIN: Copied from https://bitcointalk.org/index.php?topic=1026.0 (public domain)
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)
def b58encode(v):
  """ encode v, which is a string of bytes, to base58.
  """

  long_value = 0
  for (i, c) in enumerate(v[::-1]):
    long_value += (256**i) * ord(c)

  result = ''
  while long_value >= __b58base:
    div, mod = divmod(long_value, __b58base)
    result = __b58chars[mod] + result
    long_value = div
  result = __b58chars[long_value] + result

  # Bitcoin does a little leading-zero-compression:
  # leading 0-bytes in the input become leading-1s
  nPad = 0
  for c in v:
    if c == '\0': nPad += 1
    else: break

  return (__b58chars[0]*nPad) + result


def KDF(z):
    m = hashlib.sha256(int_to_string(z))

    return m

class KeyPair(object):


    @classmethod
    def new_keypair(self):
        curve = SECP_256k1()
        G = curve.generator()

        self.private = string_to_int(os.urandom(curve.coord_size))
        self.public = self.private * G

        priv_b58 = b58encode(int_to_string(self.private))
        pub_b58_x = b58encode(int_to_string(self.public.x))
        pub_b58_y = b58encode(int_to_string(self.public.y))

        key_agreement = self.private * self.public

        key = KDF(key_agreement)  #MAC

        return key

    def save_to_file(sharedKey, file):
        #only thing saved to the file is the agreed shared key
        file = outfile
        ofile = open(file, "w")
        ofile.write(sharedKey)

    def get_from_file(infile):
        file = infile
        for line in file:
            return line

def ecies_encryption(target_pub_key, file):
    outfile ="saved_shared_key.txt"

    #use chacha_poly_aead
    empheral_key_pair = KeyPair()
    secret_key = KDF(int_to_string((empheral_key_pair.private*target_pub_key).x))

    KeyPair.save_to_file(secret_key,outfile)

    ad=""
    iv= urandom(12)
    constant = ""

    #throw iv, constant, into cha cha
    #aad, what is it...
    alg = ChaCha_Poly_AEAD(secret_key, constant)

    # aad, iv, plain text
    message = alg.encrypt(ad, iv, file)  #returns the iv, cipher text, and tag

    return int_to_string(KeyPair.public) + message

#Cipher text includes: U + IV + ciphertext + tag (look at presentation)
def encis_decryption(sender_public_key, tag, cipher_text, infile):
    #with the public key and his private key, v, Bob will multiply both elements in order to produce the shared secret value
    empheral_key_pair = KeyPair()
    shared_secret_value = sender_public_key * empheral_key_pair.private

    m = KDF(shared_secret_value)

    #check the save key from the file
    key_from_infile = KeyPair.get_from_file(infile)

    constant =""

    ####
    #I don't know how to check the tags
    ####
    if key_from_infile == m:
        ad = ""
        alg = ChaCha_Poly_AEAD(shared_secret_value, constant)
        message = alg.decrypt(ad, cipher_text)
        return message

    else:
        return "REJECTION: FAILURE IN MAC VERIFICATION"


# TODO: if there isn't a file...
def main(argv):
    inputfile = ""
    outputfile =""


    try:
        opts, args = getopt.getopt(argv, "hi:o:e:d:", ["ifile=","ofile="])
    except getopt.GetoptError:
        print ("main.py -i <inputfile> -o <output file>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print ("main.py -i <inputfile> -o <output file> ")
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
        elif opt in ("-e", "--encrypt"):
            target_public_key = input("target public key required:")
            ecies_encryption(target_public_key, inputfile)

        elif opt in ("-d", "--decrypt"):
            # sender_public_key, tag, cipher_text, infile
            sender_public_key = input("sender's public key required:")
            encis_decryption(sender_public_key, tag, inputfile, infile)
        else:
            print()


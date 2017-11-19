
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

def key_dev(z):
    # HMAC, in this case, you hashlib sha 256
    m = hashlib.sha256(int_to_string(z))
    return m

class KeyPair(object):

    @classmethod
    def new_keypair(self):
        curve = SECP_256k1()
        G = curve.generator()
        self.private = string_to_int(os.urandom(curve.coord_size))
        self.public = self.private * G
        # self.private = urandom(curve.coord_size)
        # self.public = curve.generator()

        priv_b58 = b58encode(int_to_string(u_private))
        pub_b58_x = b58encode(int_to_string(U_public.x))
        pub_b58_y = b58encode(int_to_string(U_public.y))

        z = self.private * self.public

        V = key_dev(z)  #MAC

        return V

    def save_to_file(vector, file):
        file = outfile
        ofile = open(file, "w")
        ofile.write(vector)

    def get_from_file(infile):
        file = infile
        for line in file:
            return line

def ecies_encryption(target_pub_key, file):
    #use chacha_poly_aead
    empheral_key_pair = KeyPair()
    secret_key = key_dev(int_to_string((empheral_key_pair.private*target_pub_key).x))

    iv= urandom(12)
    constant = ""

    #throw iv, constant, into cha cha
    #aad, what is it...
    alg = ChaCha_Poly_AEAD(secret_key ,constant)
    #aad, iv, plain text
    message = alg.encrypt("", iv, file)
    #reult is the concatenation of the symmetric encryption key
    tag = int_to_string(secret_key) + message

    return tag

#Cipher text includes: U + IV + ciphertext + tag (look at presentation)
def encis_decryption(ephemeral_pub_key, tag, cipher_text):
    #with the public key and his private key, v, Bob will multiply both elements in order to produce the shared secret value


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
            ecies_encrypt(public_key, data) #TODO: change this

        elif opt in ("-d", "--decrypt"):
            encis_decrypt(secret_key, data)  #TODO: change this
        else:
            print()


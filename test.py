from bsaes import BitslicedAES128ECB
from Crypto.Cipher import AES
import os

def check(key, pt):
	bsaes = BitslicedAES128ECB(key=key)
	bs_ct = bsaes.encrypt(pt)
	print("bs_ct:", bs_ct.hex())

	ogaes = AES.new(key=key, mode=AES.MODE_ECB)
	og_ct = ogaes.encrypt(pt)
	print("og_ct:", og_ct.hex())

	assert(bs_ct == og_ct)


KEY = bytes(range(16))
PLAINTEXT = bytes(range(16))

check(KEY, PLAINTEXT)
check(os.urandom(16), os.urandom(128))

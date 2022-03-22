from bsaes import BitslicedAES128ECB
import pyaes
from timeit import timeit
import os

TEST_SIZES =   [0x10, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x10000, 0x100000, 0x400000, 0x1000000]
TEST_REPEATS = [100,  100,   100,   100,   100,   100,    10,      4,        2,        1]

aes = BitslicedAES128ECB(key=bytes(range(0x10)))


for size, repeats in zip(TEST_SIZES, TEST_REPEATS):
	repeats = 1
	msg = os.urandom(size)
	#pyaes_aes = pyaes.Encrypter(pyaes.AESModeOfOperationECB(bytes(range(0x10))))
	time = timeit(lambda: aes.encrypt(msg), number=repeats)
	#time = timeit(lambda: pyaes_aes.feed(msg) + pyaes_aes.feed(), number=repeats)
	
	print(f"Size: 0x{size:x} bytes. Speed: {size*repeats/0x100000/time} MB/s")

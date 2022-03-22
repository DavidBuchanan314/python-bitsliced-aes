from util import aes_128_key_expansion

class BitslicedAES128ECB():
	def __init__(self, key):
		if len(key) != 16:
			raise Exception("Only 128-bit keys are supported.")

		self._rkeys = aes_128_key_expansion(key)


	def encrypt(self, message):
		if len(message) % 16:
			raise Exception("Message length must be a multiple of 16 bytes")

		self._slice(message)

		self._add_round_key(self._rkeys[0])
		for i in range(1, 10):
			self._sub_bytes()
			self._shift_rows()
			self._mix_columns()
			self._add_round_key(self._rkeys[i])
		self._sub_bytes()
		self._shift_rows()
		self._add_round_key(self._rkeys[-1])

		return self._unslice()


	def _slice(self, data):
		self._byte_length = len(data)

		# we add an extra 1-bit to the zeroes so that bitwise operations against it
		# will *hopefully* take the same amount of time as with the ones. The
		# ones also have this extra bit, for maximum symmetry.
		self._ones   = int.from_bytes(b"\xff"*((self._byte_length+127)//128) + b"\x01", "little")
		self._zeroes = int.from_bytes(b"\x00"*((self._byte_length+127)//128) + b"\x01", "little")

		n = f"{int.from_bytes(data, 'little'):0{self._byte_length*8}b}"
		self._slices = [int(n[127-i::128], 2) for i in range(128)]


	def _unslice(self):
		data = bytearray(self._byte_length*8)
		for i in range(128):
			data[127-i::128] = f"{self._slices[i]:0{self._byte_length//16}b}"[-self._byte_length//16:].encode()
		return int(data, 2).to_bytes(self._byte_length, "little")


	def _sub_bytes(self):
		for i in range(0, 128, 8):
			self._slices[i:i+8] = self._sbox(self._slices[i:i+8])


	def _mix_columns(self):
		for i in range(0, 128, 32):
			self._slices[i:i+32] = self._mix_column(self._slices[i:i+32])


	def _add_round_key(self, rkey):
		for i in range(128):
			self._slices[i] ^= [self._zeroes, self._ones][(rkey>>i)&1] # TODO: make contant-timeier


	# https://github.com/conorpp/bitsliced-aes/blob/master/bs.c
	def _sbox(self, U):
		T1 = U[7] ^ U[4]
		T2 = U[7] ^ U[2]
		T3 = U[7] ^ U[1]
		T4 = U[4] ^ U[2]
		T5 = U[3] ^ U[1]
		T6 = T1 ^ T5
		T7 = U[6] ^ U[5]
		T8 = U[0] ^ T6
		T9 = U[0] ^ T7
		T10 = T6 ^ T7
		T11 = U[6] ^ U[2]
		T12 = U[5] ^ U[2]
		T13 = T3 ^ T4
		T14 = T6 ^ T11
		T15 = T5 ^ T11
		T16 = T5 ^ T12
		T17 = T9 ^ T16
		T18 = U[4] ^ U[0]
		T19 = T7 ^ T18
		T20 = T1 ^ T19
		T21 = U[1] ^ U[0]
		T22 = T7 ^ T21
		T23 = T2 ^ T22
		T24 = T2 ^ T10
		T25 = T20 ^ T17
		T26 = T3 ^ T16
		T27 = T1 ^ T12
		M1 = T13 & T6
		M2 = T23 & T8
		M3 = T14 ^ M1
		M4 = T19 & U[0]
		M5 = M4 ^ M1
		M6 = T3 & T16
		M7 = T22 & T9
		M8 = T26 ^ M6
		M9 = T20 & T17
		M10 = M9 ^ M6
		M11 = T1 & T15
		M12 = T4 & T27
		M13 = M12 ^ M11
		M14 = T2 & T10
		M15 = M14 ^ M11
		M16 = M3 ^ M2
		M17 = M5 ^ T24
		M18 = M8 ^ M7
		M19 = M10 ^ M15
		M20 = M16 ^ M13
		M21 = M17 ^ M15
		M22 = M18 ^ M13
		M23 = M19 ^ T25
		M24 = M22 ^ M23
		M25 = M22 & M20
		M26 = M21 ^ M25
		M27 = M20 ^ M21
		M28 = M23 ^ M25
		M29 = M28 & M27
		M30 = M26 & M24
		M31 = M20 & M23
		M32 = M27 & M31
		M33 = M27 ^ M25
		M34 = M21 & M22
		M35 = M24 & M34
		M36 = M24 ^ M25
		M37 = M21 ^ M29
		M38 = M32 ^ M33
		M39 = M23 ^ M30
		M40 = M35 ^ M36
		M41 = M38 ^ M40
		M42 = M37 ^ M39
		M43 = M37 ^ M38
		M44 = M39 ^ M40
		M45 = M42 ^ M41
		M46 = M44 & T6
		M47 = M40 & T8
		M48 = M39 & U[0]
		M49 = M43 & T16
		M50 = M38 & T9
		M51 = M37 & T17
		M52 = M42 & T15
		M53 = M45 & T27
		M54 = M41 & T10
		M55 = M44 & T13
		M56 = M40 & T23
		M57 = M39 & T19
		M58 = M43 & T3
		M59 = M38 & T22
		M60 = M37 & T20
		M61 = M42 & T1
		M62 = M45 & T4
		M63 = M41 & T2
		L0 = M61 ^ M62
		L1 = M50 ^ M56
		L2 = M46 ^ M48
		L3 = M47 ^ M55
		L4 = M54 ^ M58
		L5 = M49 ^ M61
		L6 = M62 ^ L5
		L7 = M46 ^ L3
		L8 = M51 ^ M59
		L9 = M52 ^ M53
		L10 = M53 ^ L4
		L11 = M60 ^ L2
		L12 = M48 ^ M51
		L13 = M50 ^ L0
		L14 = M52 ^ M61
		L15 = M55 ^ L1
		L16 = M56 ^ L0
		L17 = M57 ^ L1
		L18 = M58 ^ L8
		L19 = M63 ^ L4
		L20 = L0 ^ L1
		L21 = L1 ^ L7
		L22 = L3 ^ L12
		L23 = L18 ^ L2
		L24 = L15 ^ L9
		L25 = L6 ^ L10
		L26 = L7 ^ L9
		L27 = L8 ^ L10
		L28 = L11 ^ L14
		L29 = L11 ^ L17
		S = [None]*8
		S[7] = L6 ^ L24
		S[6] = L16 ^ L26 ^ self._ones
		S[5] = L19 ^ L28 ^ self._ones
		S[4] = L6 ^ L21
		S[3] = L20 ^ L22
		S[2] = L25 ^ L29
		S[1] = L13 ^ L27 ^ self._ones
		S[0] = L6 ^ L23 ^ self._ones
		return S


	def _shift_rows(self):
		Bp = [None]*128
		offsetr0 = 0
		offsetr1 = 32
		offsetr2 = 64
		offsetr3 = 96
		B0 = 0
		B1 = 32
		B2 = 64
		B3 = 96
		for _ in range(4):
			Br0 = self._slices[offsetr0:offsetr0+8]
			Br1 = self._slices[offsetr1:offsetr1+8]
			Br2 = self._slices[offsetr2:offsetr2+8]
			Br3 = self._slices[offsetr3:offsetr3+8]

			Bp[B0 + 0] = Br0[0]
			Bp[B0 + 1] = Br0[1]
			Bp[B0 + 2] = Br0[2]
			Bp[B0 + 3] = Br0[3]
			Bp[B0 + 4] = Br0[4]
			Bp[B0 + 5] = Br0[5]
			Bp[B0 + 6] = Br0[6]
			Bp[B0 + 7] = Br0[7]
			Bp[B1 + 0] = Br1[0]
			Bp[B1 + 1] = Br1[1]
			Bp[B1 + 2] = Br1[2]
			Bp[B1 + 3] = Br1[3]
			Bp[B1 + 4] = Br1[4]
			Bp[B1 + 5] = Br1[5]
			Bp[B1 + 6] = Br1[6]
			Bp[B1 + 7] = Br1[7]
			Bp[B2 + 0] = Br2[0]
			Bp[B2 + 1] = Br2[1]
			Bp[B2 + 2] = Br2[2]
			Bp[B2 + 3] = Br2[3]
			Bp[B2 + 4] = Br2[4]
			Bp[B2 + 5] = Br2[5]
			Bp[B2 + 6] = Br2[6]
			Bp[B2 + 7] = Br2[7]
			Bp[B3 + 0] = Br3[0]
			Bp[B3 + 1] = Br3[1]
			Bp[B3 + 2] = Br3[2]
			Bp[B3 + 3] = Br3[3]
			Bp[B3 + 4] = Br3[4]
			Bp[B3 + 5] = Br3[5]
			Bp[B3 + 6] = Br3[6]
			Bp[B3 + 7] = Br3[7]

			offsetr0 = (offsetr0 + 128//16 + 128//4) & 0x7f
			offsetr1 = (offsetr1 + 128//16 + 128//4) & 0x7f
			offsetr2 = (offsetr2 + 128//16 + 128//4) & 0x7f
			offsetr3 = (offsetr3 + 128//16 + 128//4) & 0x7f

			B0 += 8
			B1 += 8
			B2 += 8
			B3 += 8

		self._slices = Bp


	def _mix_column(self, B):
		A0 = 0
		A1 = 8
		A2 = 16
		A3 = 24

		Bp = [None]*32
		of = B[A0+7] ^ B[A1+7]

		Bp[A0+0] =                     B[A1+0] ^ B[A2+0] ^ B[A3+0] ^ of
		Bp[A0+1] = B[A0+0] ^ B[A1+0] ^ B[A1+1] ^ B[A2+1] ^ B[A3+1] ^ of
		Bp[A0+2] = B[A0+1] ^ B[A1+1] ^ B[A1+2] ^ B[A2+2] ^ B[A3+2]
		Bp[A0+3] = B[A0+2] ^ B[A1+2] ^ B[A1+3] ^ B[A2+3] ^ B[A3+3] ^ of
		Bp[A0+4] = B[A0+3] ^ B[A1+3] ^ B[A1+4] ^ B[A2+4] ^ B[A3+4] ^ of
		Bp[A0+5] = B[A0+4] ^ B[A1+4] ^ B[A1+5] ^ B[A2+5] ^ B[A3+5]
		Bp[A0+6] = B[A0+5] ^ B[A1+5] ^ B[A1+6] ^ B[A2+6] ^ B[A3+6]
		Bp[A0+7] = B[A0+6] ^ B[A1+6] ^ B[A1+7] ^ B[A2+7] ^ B[A3+7]

		of = B[A1+7] ^ B[A2+7]

		Bp[A1+0] = B[A0+0]                     ^ B[A2+0] ^ B[A3+0] ^ of
		Bp[A1+1] = B[A0+1] ^ B[A1+0] ^ B[A2+0] ^ B[A2+1] ^ B[A3+1] ^ of
		Bp[A1+2] = B[A0+2] ^ B[A1+1] ^ B[A2+1] ^ B[A2+2] ^ B[A3+2]
		Bp[A1+3] = B[A0+3] ^ B[A1+2] ^ B[A2+2] ^ B[A2+3] ^ B[A3+3] ^ of
		Bp[A1+4] = B[A0+4] ^ B[A1+3] ^ B[A2+3] ^ B[A2+4] ^ B[A3+4] ^ of
		Bp[A1+5] = B[A0+5] ^ B[A1+4] ^ B[A2+4] ^ B[A2+5] ^ B[A3+5]
		Bp[A1+6] = B[A0+6] ^ B[A1+5] ^ B[A2+5] ^ B[A2+6] ^ B[A3+6]
		Bp[A1+7] = B[A0+7] ^ B[A1+6] ^ B[A2+6] ^ B[A2+7] ^ B[A3+7]

		of = B[A2+7] ^ B[A3+7]

		Bp[A2+0] = B[A0+0] ^ B[A1+0]                     ^ B[A3+0] ^ of
		Bp[A2+1] = B[A0+1] ^ B[A1+1] ^ B[A2+0] ^ B[A3+0] ^ B[A3+1] ^ of
		Bp[A2+2] = B[A0+2] ^ B[A1+2] ^ B[A2+1] ^ B[A3+1] ^ B[A3+2]
		Bp[A2+3] = B[A0+3] ^ B[A1+3] ^ B[A2+2] ^ B[A3+2] ^ B[A3+3] ^ of
		Bp[A2+4] = B[A0+4] ^ B[A1+4] ^ B[A2+3] ^ B[A3+3] ^ B[A3+4] ^ of
		Bp[A2+5] = B[A0+5] ^ B[A1+5] ^ B[A2+4] ^ B[A3+4] ^ B[A3+5]
		Bp[A2+6] = B[A0+6] ^ B[A1+6] ^ B[A2+5] ^ B[A3+5] ^ B[A3+6]
		Bp[A2+7] = B[A0+7] ^ B[A1+7] ^ B[A2+6] ^ B[A3+6] ^ B[A3+7]

		of = B[A0+7] ^ B[A3+7]

		Bp[A3+0] = B[A0+0] ^           B[A1+0] ^ B[A2+0]           ^ of
		Bp[A3+1] = B[A0+1] ^ B[A0+0] ^ B[A1+1] ^ B[A2+1] ^ B[A3+0] ^ of
		Bp[A3+2] = B[A0+2] ^ B[A0+1] ^ B[A1+2] ^ B[A2+2] ^ B[A3+1]
		Bp[A3+3] = B[A0+3] ^ B[A0+2] ^ B[A1+3] ^ B[A2+3] ^ B[A3+2] ^ of
		Bp[A3+4] = B[A0+4] ^ B[A0+3] ^ B[A1+4] ^ B[A2+4] ^ B[A3+3] ^ of
		Bp[A3+5] = B[A0+5] ^ B[A0+4] ^ B[A1+5] ^ B[A2+5] ^ B[A3+4]
		Bp[A3+6] = B[A0+6] ^ B[A0+5] ^ B[A1+6] ^ B[A2+6] ^ B[A3+5]
		Bp[A3+7] = B[A0+7] ^ B[A0+6] ^ B[A1+7] ^ B[A2+7] ^ B[A3+6]

		return Bp

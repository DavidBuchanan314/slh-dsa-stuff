r"""
/!\ DANGER /!\
This implementation does not conform to any particular spec and is insecure.

vanilla WOTS as described in https://www.geeksforgeeks.org/winternitz-one-time-signature-scheme/

(todo, find a good non-geeksforgeeks source lol, the article itself is fine (other than not citing sources) but I hate the site...)

Another resource, more technical: https://www.di-mgt.com.au/pqc-03-winternitz.html

Per above, what's implemented below is insecure because:

> "if an attacker can find a message digest where each index value is greater than the original, they can forge a signature over the new message."

At time of writing, I don't really understand how a checksum fixes this... seems equivalent to just making the hash longer?
"""

from typing import Tuple, List
from hashlib import sha256
import os

# sha256 = 32x 8-bit bytes

def wots_keygen() -> Tuple[bytes, List[bytes]]:
	seed = os.urandom(32) # essentially the privkey
	pubkey = []
	for i in range(32):
		value = seed
		for j in range(256):
			value = sha256(value + bytes([i, j])).digest()
		pubkey.append(value)
	return seed, pubkey

def wots_sign(seed: bytes, msg: bytes) -> List[bytes]:
	msg_hash = sha256(msg).digest()
	signature = []
	for i in range(32):
		value = seed
		for j in range(256 - msg_hash[i]):
			value = sha256(value + bytes([i, j])).digest()
		signature.append(value)
	return signature

def wots_verify(pubkey: List[bytes], signature: List[bytes], msg: bytes) -> None:
	msg_hash = sha256(msg).digest()
	for i in range(32):
		value = signature[i]
		for j in range(256 -  msg_hash[i], 256):
			value = sha256(value + bytes([i, j])).digest()
		if value != pubkey[i]:
			raise Exception("bad signature")
	# verification successful!

if __name__ == "__main__":
	privkey, pubkey = wots_keygen()
	signature = wots_sign(privkey, b"hello")
	wots_verify(pubkey, signature, b"hello")

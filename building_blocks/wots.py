r"""
/!\ DANGER /!\
This implementation does not conform to any particular spec and is (probably) insecure.

vanilla WOTS as described in https://www.geeksforgeeks.org/winternitz-one-time-signature-scheme/

(todo, find a good non-geeksforgeeks source lol, the article itself is fine (other than not citing sources, and describing an insecure scheme) but I hate the site...)

Another resource, more technical: https://www.di-mgt.com.au/pqc-03-winternitz.html

Per above, what's implemented below is insecure because:

> "if an attacker can find a message digest where each index value is greater than the original, they can forge a signature over the new message."

At time of writing, I don't really understand how a checksum fixes this... seems equivalent to just making the hash longer? (although I can see that a long enough hash *would* fix it, probabilistically)

ohhhh. the checksum is an actuall sum, not just in the colloquial sense of a checksum.

"The checksum computed here ensures that if such a message digest exists, then the checksum will produce at least one index less than the original, which cannot be forged."
"""

from typing import Tuple, List
from hashlib import sha256
import os

# sha256 = 32x 8-bit bytes

def wots_keygen() -> Tuple[bytes, List[bytes]]:
	seed = os.urandom(32) # essentially the privkey
	pubkey = []
	for i in range(32 + 2):
		value = seed
		for j in range(256):
			value = sha256(value + bytes([i, j])).digest()
		pubkey.append(value)
	return seed, pubkey

def calc_checksum(msg: bytes) -> bytes: # len = 2
	checksum = 256 * len(msg) - sum(msg)
	return checksum.to_bytes(2, "little")

def wots_sign(seed: bytes, msg: bytes) -> List[bytes]:
	msg_hash = sha256(msg).digest()
	msg_hash += calc_checksum(msg_hash)
	signature = []
	for i in range(32 + 2):
		value = seed
		for j in range(256 - msg_hash[i]):
			value = sha256(value + bytes([i, j])).digest()
		signature.append(value)
	return signature

def wots_verify(pubkey: List[bytes], signature: List[bytes], msg: bytes) -> None:
	msg_hash = sha256(msg).digest()
	msg_hash += calc_checksum(msg_hash)
	for i in range(32 + 2):
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

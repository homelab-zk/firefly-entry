"""Usage: python3 gen_pin_hash.py   -> asks for the PIN twice, prints PIN_HASH value for .env
(python3 gen_pin_hash.py <pin> still works, but leaves the PIN in shell history.)"""
import getpass, hashlib, os, sys

if len(sys.argv) > 1:
    pin = sys.argv[1]
else:
    pin = getpass.getpass("New PIN: ")
    if pin != getpass.getpass("Repeat PIN: "):
        sys.exit("PINs do not match")
if not (pin.isdigit() and len(pin) >= 4):
    sys.exit("PIN must be at least 4 digits")
salt = os.urandom(16)
h = hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
print(f"scrypt:{salt.hex()}:{h.hex()}")

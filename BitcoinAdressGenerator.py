import os, binascii, random, base58, hashlib
from ellipticcurve.privateKey import PrivateKey


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

priv = binascii.hexlify(os.urandom(32)).decode('utf-8')
pk = PrivateKey().fromString(bytes.fromhex(priv))
publ_key = '04' + pk.publicKey().toString().hex()

int_x = int((publ_key[2:66]), 16)        
int_y = int((publ_key[66:130]), 16)
if int_y % 2 == 0:
	pre = "02"
else:
	pre = "03"
publ_key_comp = pre + (publ_key[2:66])

non_comp_adres = base58.b58encode((b"\x00" + (ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest())) + (hashlib.sha256(hashlib.sha256((b"\x00" + (ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()))).digest()).digest()[:4])).decode('utf-8') + "\n"
comp_adres = base58.b58encode((b"\x00" + (ripemd160(hashlib.sha256(binascii.unhexlify(publ_key_comp)).digest()).digest())) + (hashlib.sha256(hashlib.sha256((b"\x00" + (ripemd160(hashlib.sha256(binascii.unhexlify(publ_key_comp)).digest()).digest()))).digest()).digest()[:4])).decode('utf-8') + "\n"
segwit_adres = base58.b58encode((b"\x05" + (ripemd160(hashlib.sha256(binascii.unhexlify(('0014' + binascii.hexlify((ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest())).decode()))).digest()).digest())) + (hashlib.sha256(hashlib.sha256((b"\x05" + (ripemd160(hashlib.sha256(binascii.unhexlify(('0014' + binascii.hexlify((ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest())).decode()))).digest()).digest()))).digest()).digest()[:4])).decode('utf-8') + "\n"
segwit_comp_adres = base58.b58encode((b"\x05" + (ripemd160(hashlib.sha256(binascii.unhexlify(('0014' + binascii.hexlify((ripemd160(hashlib.sha256(binascii.unhexlify(publ_key_comp)).digest()).digest())).decode()))).digest()).digest())) + (hashlib.sha256(hashlib.sha256((b"\x05" + (ripemd160(hashlib.sha256(binascii.unhexlify(('0014' + binascii.hexlify((ripemd160(hashlib.sha256(binascii.unhexlify(publ_key_comp)).digest()).digest())).decode()))).digest()).digest()))).digest()).digest()[:4])).decode('utf-8') + "\n"

print("NON-COMPRESSED ADDRESS = " +  str(non_comp_adres))
print("COMPRESSED ADDRESS = " +  str(comp_adres))
print("SEGWIT ADDRESS = " +  str(segwit_adres))
print("NON-COMPRESSED SEGWIT ADDRESS = " +  str(segwit_comp_adres))
print("PRIVATE KEY(HEX) = " +  str(priv))

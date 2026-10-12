"""Primitiva de bloque y utilidades. Lo unico que se les da hecho.
AES sobre EXACTAMENTE 16 bytes. Los modos los implementan ustedes."""

def _cargar():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        def e(k, b):
            c = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
            return c.update(b) + c.finalize()
        def d(k, b):
            x = Cipher(algorithms.AES(k), modes.ECB()).decryptor()
            return x.update(b) + x.finalize()
        return e, d
    except ImportError:
        from Crypto.Cipher import AES
        return (lambda k, b: AES.new(k, AES.MODE_ECB).encrypt(b),
                lambda k, b: AES.new(k, AES.MODE_ECB).decrypt(b))

aes_e, aes_d = _cargar()

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def bloques(datos, n=16):
    return [datos[i:i + n] for i in range(0, len(datos), n)]

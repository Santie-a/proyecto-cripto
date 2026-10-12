#!/usr/bin/env python3
"""
================================================================
  VERIFICADOR DEL REGISTRO DE LICENCIAS
================================================================

Esta es la herramienta que usa el mercado para comprobar que su
registro esta intacto. Ustedes la reciben para poder poner a prueba
lo que construyan.

Verifica las dos cadenas:

  CBC   c_i = E_k(m_i XOR c_{i-1})      necesita la clave, que esta
                                        dentro de registro_cbc.json

  DM    h_i = E_{m_i}(h_{i-1}) XOR h_{i-1}   no necesita ninguna clave:
                                        recomputa y compara contra el
                                        sello PUBLICADO (sello_publicado.txt),
                                        no contra un valor del propio archivo

USO
---
    python3 verificador.py cbc registro_cbc.json
    python3 verificador.py dm  registro_dm.json

Si alteran un registro y quieren ver si el verificador se da cuenta,
pasenle su archivo modificado:

    python3 verificador.py cbc mi_registro_falso.json
"""

import sys, json, re

BLK = 16


def _aes():
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


E, D = _aes()
xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
bl = lambda d, n=BLK: [d[i:i+n] for i in range(0, len(d), n)]

FORMATO = re.compile(r"^TX\d{2}:L\d{4}:[A-Z]{2}-[A-Z] $")


def ver_cbc(ruta):
    d = json.load(open(ruta))
    k = bytes.fromhex(d["clave"]); iv = bytes.fromhex(d["iv"])
    c = bytes.fromhex(d["cadena"])

    prev, entradas = iv, []
    for b in bl(c):
        entradas.append(xor(D(k, b), prev)); prev = b

    print("\n  Registro leido de la cadena CBC:\n")
    ok = True
    for i, m in enumerate(entradas, 1):
        try:
            s = m.decode("latin-1")
        except Exception:
            s = repr(m); ok = False
        bien = bool(FORMATO.match(s))
        ok &= bien
        print("    entrada %d: %-20r %s" % (i, s, "" if bien else "<-- formato invalido"))

    print()
    if ok:
        print("  >>> CADENA VALIDA. Todas las entradas estan bien formadas")
        print("      y el encadenamiento es consistente.\n")
        print("      Pregunta para el informe: el verificador acepto este")
        print("      registro. Eso prueba que nadie lo altero?\n")
    else:
        print("  >>> CADENA INVALIDA. Hay entradas mal formadas.\n")


def leer_ancla(ruta="sello_publicado.txt"):
    """El sello de referencia NO se lee del archivo que se esta verificando:
    se lee del ancla publicada, que el custodio del registro no controla."""
    for linea in open(ruta):
        linea = linea.strip()
        if linea and not linea.startswith("#"):
            return linea
    raise ValueError("no encontre el sello en %s" % ruta)


def ver_dm(ruta, ancla="sello_publicado.txt"):
    d = json.load(open(ruta))
    h = bytes.fromhex(d["h0"])
    entradas = [e.encode("latin-1") for e in d["entradas"]]

    print("\n  Recomputando la cadena Davies-Meyer:\n")
    print("    h0 = %s" % h.hex())
    for i, m in enumerate(entradas, 1):
        h = xor(E(m, h), h)
        print("    h%d = E_{m%d}(h%d) XOR h%d = %s" % (i, i, i - 1, i - 1, h.hex()))

    esperado = leer_ancla(ancla)
    print("\n    sello recomputado de este archivo : %s" % h.hex())
    print("    sello PUBLICADO por el mercado    : %s\n" % esperado)
    if h.hex() == esperado:
        print("  >>> SELLO CORRECTO. El registro coincide con el publicado.\n")
    else:
        print("  >>> SELLO INCORRECTO. Este registro NO es el publicado.\n")
    print("      Dos cosas que conviene notar:\n")
    print("      1. Aqui NO se uso ninguna clave: solo se recomputo.")
    print("      2. El sello de referencia NO sale de este archivo, sino de")
    print("         sello_publicado.txt. Si saliera del mismo archivo que se")
    print("         esta verificando, cualquiera podria cambiar una entrada,")
    print("         recalcular y sustituir tambien el sello.\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(0)
    modo, ruta = sys.argv[1], sys.argv[2]
    if modo == "cbc":
        ver_cbc(ruta)
    elif modo == "dm":
        ver_dm(ruta)
    else:
        print("Modo desconocido. Use 'cbc' o 'dm'.")

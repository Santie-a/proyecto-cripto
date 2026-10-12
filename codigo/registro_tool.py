#!/usr/bin/env python3
"""
================================================================
  HERRAMIENTA DEL REGISTRO
================================================================

La parte aburrida ya esta resuelta: abrir los archivos, leer los
campos, partir en bloques y guardar. Ustedes escriben las funciones
de criptografia, que son el ejercicio.

COMO SE USA
-----------
  1. Pongan este archivo junto a registro_cbc.json y registro_dm.json
  2. Miren que hay adentro:   python3 registro_tool.py ver
  3. Completen las funciones marcadas mas abajo, en este orden:
        cbc_descifrar   -> para leer el registro       (ejercicio 1)
        cbc_cifrar      -> para reescribir la historia (ejercicio 2)
        davies_meyer    -> para la otra cadena         (ejercicio 3)
  4. Vayan probando:
        python3 registro_tool.py leer
        python3 registro_tool.py romper 3
        python3 registro_tool.py reescribir
        python3 registro_tool.py sello
  5. Comprueben con el verificador del mercado:
        python3 verificador.py cbc falsificado.json

Nunca se modifican los archivos originales.
"""

import sys, json
from cripto import aes_e, aes_d, xor, bloques

CBC = "registro_cbc.json"
DM  = "registro_dm.json"

HISTORIA_FALSA = [b"TX01:L0042:EQ-A ", b"TX02:L0042:EQ-A ",
                  b"TX03:L0177:EQ-A ", b"TX04:L0177:EQ-B "]


def cargar_cbc():
    d = json.load(open(CBC))
    return bytes.fromhex(d["clave"]), bytes.fromhex(d["iv"]), bytes.fromhex(d["cadena"])


def cargar_dm():
    d = json.load(open(DM))
    sello = None
    for linea in open("sello_publicado.txt"):
        linea = linea.strip()
        if linea and not linea.startswith("#"):
            sello = linea; break
    return bytes.fromhex(d["h0"]), [e.encode("latin-1") for e in d["entradas"]], sello


# ================================================================
#   LO QUE TIENEN QUE ESCRIBIR
# ================================================================

def cbc_descifrar(k, iv, cadena):
    """Recupera la lista de entradas a partir de la cadena cifrada.

    La recurrencia es   c_i = E_k( m_i XOR c_{i-1} )   con c_0 = IV.
    Ustedes ya despejaron m_i en el Taller 0.

    Herramientas: aes_d(k, bloque), xor(a, b), bloques(datos)
    Devuelve: una lista de bloques de 16 bytes.
    """
    entradas, anterior = [], iv
    for c in bloques(cadena):
        entradas.append(xor(aes_d(k, c), anterior))   # m_i = D_k(c_i) XOR c_{i-1}
        anterior = c
    return entradas


def cbc_cifrar(k, iv, entradas):
    """Construye la cadena a partir de una lista de entradas.

    Es la recurrencia tal como esta escrita, sin despejar nada.
    Herramientas: aes_e(k, bloque), xor(a, b)
    Devuelve: los bloques cifrados pegados, en bytes.
    """
    salida, anterior = b"", iv
    for m in entradas:
        assert len(m) == 16
        anterior = aes_e(k, xor(m, anterior))         # c_i = E_k(m_i XOR c_{i-1})
        salida += anterior
    return salida


def davies_meyer(h0, entradas):
    """Encadena las entradas con  h_i = E_{m_i}( h_{i-1} ) XOR h_{i-1}

    OJO con el orden de los argumentos: el MENSAJE va como clave.
    Es aes_e(m, h), no aes_e(h, m). Es el error mas comun.

    Devuelve: el valor final, 16 bytes.
    """
    h = h0
    for m in entradas:
        assert len(m) == 16
        h = xor(aes_e(m, h), h)                       # el mensaje va como clave
    return h


# ================================================================

def _falta(e):
    print("\n  %s\n" % e); return None


def cmd_ver():
    k, iv, c = cargar_cbc()
    print("\n  === registro_cbc.json ===")
    print("    clave  : %s   <- si, se las damos a proposito" % k.hex())
    print("    iv     : %s" % iv.hex())
    print("    cadena : %d bloques de 16 bytes" % (len(c) // 16))
    for i, b in enumerate(bloques(c), 1):
        print("       c%d = %s" % (i, b.hex()))
    h0, ents, sello = cargar_dm()
    print("\n  === registro_dm.json ===")
    print("    h0          : %s" % h0.hex())
    print("    (el sello NO esta en este archivo: esta en sello_publicado.txt)")
    print("    sello publicado : %s" % sello)
    print("    entradas    : (estan EN CLARO, aqui no se oculta nada)")
    for i, m in enumerate(ents, 1):
        print("       m%d = %r" % (i, m.decode("latin-1")))
    print()


def cmd_leer():
    k, iv, c = cargar_cbc()
    try:
        ents = cbc_descifrar(k, iv, c)
    except NotImplementedError as e:
        return _falta(e)
    print("\n  Registro recuperado:")
    for i, m in enumerate(ents, 1):
        try:
            print("    entrada %d: %r" % (i, m.decode("latin-1")))
        except Exception:
            print("    entrada %d: %s  (ilegible)" % (i, m.hex()))
    print()


def cmd_romper(j):
    k, iv, c = cargar_cbc()
    try:
        bien = cbc_descifrar(k, iv, c)
    except NotImplementedError as e:
        return _falta(e)
    bl = bloques(c)
    bl[j - 1] = bytes([bl[j - 1][0] ^ 0x40]) + bl[j - 1][1:]
    mal = cbc_descifrar(k, iv, b"".join(bl))
    print("\n  Dañando el primer byte de c%d:\n" % j)
    for i, (a, b) in enumerate(zip(bien, mal), 1):
        dif = sum(1 for x, y in zip(a, b) if x != y)
        est = "intacta" if dif == 0 else ("alterada en %d byte" % dif if dif == 1 else "destruida (%d bytes cambiados)" % dif)
        print("    entrada %d: %-28s %s" % (i, est, b.hex()[:24] + "..."))
    print()


def cmd_reescribir():
    k, iv, c = cargar_cbc()
    try:
        nueva = cbc_cifrar(k, iv, HISTORIA_FALSA)
    except NotImplementedError as e:
        return _falta(e)
    d = json.load(open(CBC)); d["cadena"] = nueva.hex()
    json.dump(d, open("falsificado.json", "w"), indent=2)
    print("\n  Historia escrita:")
    for m in HISTORIA_FALSA:
        print("    %r" % m.decode("latin-1"))
    print("\n  Escrito: falsificado.json")
    print("  Ahora pasenlo por:  python3 verificador.py cbc falsificado.json\n")


def cmd_sello():
    h0, ents, esperado = cargar_dm()
    try:
        h = davies_meyer(h0, ents)
    except NotImplementedError as e:
        return _falta(e)
    print("\n  sello calculado por ustedes : %s" % h.hex())
    print("  sello publicado por el mercado: %s" % esperado)
    print("\n  %s\n" % ("COINCIDE. Su implementacion esta bien."
                        if h.hex() == esperado else
                        "NO COINCIDE. Revisen el orden de los argumentos de aes_e."))


if __name__ == "__main__":
    a = sys.argv[1:] or ["ayuda"]
    if   a[0] == "ver":        cmd_ver()
    elif a[0] == "leer":       cmd_leer()
    elif a[0] == "romper":     cmd_romper(int(a[1]) if len(a) > 1 else 3)
    elif a[0] == "reescribir": cmd_reescribir()
    elif a[0] == "sello":      cmd_sello()
    else:                      print(__doc__)

#!/usr/bin/env python3
"""Experimentos del Taller B que no cubre registro_tool.py.

    python3 experimentos.py

Genera:
  falsificado.json          cadena CBC reescrita (ejercicio 2)
  dm_falsificado.json       registro DM con TX02 alterado (ejercicio 3a)
  dm_con_sello_interno.json registro DM falso con su propio sello (ejercicio 3c)
"""

import json, time
from cripto import aes_e, aes_d, xor, bloques
from registro_tool import (cargar_cbc, cargar_dm, cbc_cifrar, cbc_descifrar,
                           davies_meyer, HISTORIA_FALSA)


def cadena_dm(h0, entradas):
    """Todos los valores intermedios h_0, ..., h_t."""
    hs = [h0]
    for m in entradas:
        hs.append(xor(aes_e(m, hs[-1]), hs[-1]))
    return hs


def titulo(t):
    print("\n" + "=" * 64 + "\n  " + t + "\n" + "=" * 64)


# ----------------------------------------------------------------
titulo("Ejercicio 1(a): ida y vuelta CBC")
k, iv, c = cargar_cbc()
m = cbc_descifrar(k, iv, c)
for i, x in enumerate(m, 1):
    print("  m%d = %r  (hex %s)" % (i, x.decode("latin-1"), x.hex()))
print("  cbc_cifrar(cbc_descifrar(c)) == c :", cbc_cifrar(k, iv, m) == c)

# ----------------------------------------------------------------
titulo("Ejercicio 1(b): un byte de c3 alterado (XOR 0x40 en el byte 0)")
bl = bloques(c)
bl[2] = bytes([bl[2][0] ^ 0x40]) + bl[2][1:]
mal = cbc_descifrar(k, iv, b"".join(bl))
for i, (a, b) in enumerate(zip(m, mal), 1):
    d = xor(a, b)
    print("  entrada %d: original %s" % (i, a.hex()))
    print("             danada   %s" % b.hex())
    print("             XOR      %s  (%d bytes y %d bits distintos)"
          % (d.hex(), sum(x != 0 for x in d), sum(bin(x).count("1") for x in d)))

# ----------------------------------------------------------------
titulo("Ejercicio 2(a): reescribir la historia CBC")
N = 1000
t0 = time.perf_counter()
for _ in range(N):
    nueva = cbc_cifrar(k, iv, HISTORIA_FALSA)
dt = (time.perf_counter() - t0) / N
d = json.load(open("registro_cbc.json")); d["cadena"] = nueva.hex()
json.dump(d, open("falsificado.json", "w"), indent=2)
print("  cadena falsificada:")
for i, b in enumerate(bloques(nueva), 1):
    print("    c%d* = %s   (original %s)" % (i, b.hex(), bloques(c)[i - 1].hex()))
print("  tiempo medio de la reescritura: %.1f microsegundos (promedio de %d)" % (dt * 1e6, N))

# ----------------------------------------------------------------
titulo("Ejercicio 3(a): Davies-Meyer y el intento de ataque")
h0, ents, sello = cargar_dm()
hs = cadena_dm(h0, ents)
for i, h in enumerate(hs):
    print("  h%d  = %s" % (i, h.hex()))
print("  sello publicado = %s   coincide: %s" % (sello, hs[-1].hex() == sello))

falsas = list(ents); falsas[1] = b"TX02:L0042:EQ-A "
hf = cadena_dm(h0, falsas)
print("\n  Con TX02 -> EQ-A:")
for i, h in enumerate(hf):
    print("  h%d* = %s   %s" % (i, h.hex(), "igual" if h == hs[i] else "DISTINTO"))
print("  sello publicado = %s" % sello)
d = json.load(open("registro_dm.json")); d["entradas"][1] = "TX02:L0042:EQ-A "
json.dump(d, open("dm_falsificado.json", "w"), indent=2)

# El atacante necesita, para seguir, un m4' con E_{m4'}(h3*) = sello XOR h3*.
# Es decir, una clave AES que lleve un bloque conocido a otro conocido.
objetivo = xor(bytes.fromhex(sello), hf[3])
print("\n  Para cerrar con m4' haria falta E_{m4'}(%s) = %s" % (hf[3].hex(), objetivo.hex()))
intentos, t0 = 200000, time.perf_counter()
for j in range(intentos):
    cand = b"TX04:L0177:" + j.to_bytes(5, "big")
    if aes_e(cand, hf[3]) == objetivo:
        print("  encontrado", cand); break
dt = time.perf_counter() - t0
tasa = intentos / dt
print("  %d claves probadas en %.2f s (%.0f claves/s): ninguna sirve" % (intentos, dt, tasa))
print("  tiempo esperado para 2^128 claves: %.1e anos" % (2**128 / tasa / 3.156e7))

# ----------------------------------------------------------------
titulo("Ejercicio 3(b): sin el termino final, la cadena SI se deja")
def sin_ff(h0, entradas):
    h = h0
    for m in entradas:
        h = aes_e(m, h)
    return h
S = sin_ff(h0, ents)
print("  sello de la variante h_i = E_{m_i}(h_{i-1}): %s" % S.hex())
# retroceder: h_{i-1} = D_{m_i}(h_i), con m_i publico
h = S
for i in range(4, 0, -1):
    h = aes_d(ents[i - 1], h)
    print("  retrocediendo con m%d (publico): h%d = %s" % (i, i - 1, h.hex()))
print("  se recupera h0:", h == h0)
# Falsificacion con punto de partida libre: retroceder la historia falsa
h = S
for mm in reversed(falsas):
    h = aes_d(mm, h)
print("  h0' que hace que la historia FALSA de el mismo sello: %s" % h.hex())
print("  comprobacion sin_ff(h0', falsas) == S :", sin_ff(h, falsas) == S)

# ----------------------------------------------------------------
titulo("Ejercicio 3(c): sello guardado dentro del propio archivo")
hfin = davies_meyer(h0, falsas)
d = json.load(open("registro_dm.json"))
d["entradas"][1] = "TX02:L0042:EQ-A "
d["sello_final"] = hfin.hex()
json.dump(d, open("dm_con_sello_interno.json", "w"), indent=2)
print("  historia falsa recalculada, sello nuevo: %s" % hfin.hex())
print("  un verificador que leyera el sello del archivo diria: %s"
      % ("SELLO CORRECTO" if davies_meyer(h0, [e.encode("latin-1") for e in d["entradas"]]).hex()
         == d["sello_final"] else "SELLO INCORRECTO"))
print("  contra el sello publicado: %s" % ("CORRECTO" if hfin.hex() == sello else "INCORRECTO"))

# ----------------------------------------------------------------
titulo("Ejercicio 2(c): borrar una compra SIN la clave")
d = json.load(open("registro_cbc.json"))
d["cadena"] = c[:48].hex()                       # se quita c4
json.dump(d, open("sin_ultima.json", "w"), indent=2)
d = json.load(open("registro_cbc.json"))
d["iv"], d["cadena"] = c[:16].hex(), c[16:].hex()  # se quita c1 y su IV pasa a ser c1
json.dump(d, open("sin_primera.json", "w"), indent=2)
print("  sin_ultima.json  : se borro TX04 sin usar la clave")
print("  sin_primera.json : se borro TX01 sin usar la clave (IV' = c1)")
print("  pasenlos por:  python3 verificador.py cbc sin_ultima.json")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simulador de uma Epson L395 na rede (agente SNMP v1 em UDP).

Responde como a impressora real aos comandos usados pelo l395tool:
descrição do modelo, firmware (vi), status (st), leitura/escrita da EEPROM (||)
com checagem das chaves, e liberação temporária (rw).

Serve para testar o l395tool sem encostar na impressora:
    python simulador_l395.py --porta 16100
    python l395tool.py info 127.0.0.1 --porta 16100
"""

import argparse
import hashlib
import random
import socket
import struct
import threading

from l395tool import OID_EPSON_CTRL, PerfilL395, _ber_int, _chave_escrita, _ler_tlv, _filhos, _tlv

PREFIXO_CTRL = [int(x) for x in OID_EPSON_CTRL.split(".")]
OIDS_TEXTO = {
    "1.3.6.1.2.1.25.3.2.1.3.1": None,  # hrDeviceDescr -> modelo
    "1.3.6.1.2.1.1.1.0": b"EPSON Built-in 11b/g/n Print Server",
}


def _decodificar_oid(b):
    partes = [b[0] // 40, b[0] % 40]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            partes.append(v)
            v = 0
    return partes


def _oid_ber(partes):
    out = bytearray([40 * partes[0] + partes[1]])
    for p in partes[2:]:
        g = [p & 0x7F]
        p >>= 7
        while p:
            g.append(0x80 | (p & 0x7F))
            p >>= 7
        out.extend(reversed(g))
    return _tlv(0x06, bytes(out))


class L395Simulada:
    def __init__(self, contador=6207, serie="X4HK012345", modelo=b"EPSON L395 Series",
                 bloquear_eeprom=False, ignorar_escrita=False, perda=0.0, semente=395):
        p = PerfilL395
        rnd = random.Random(semente)
        self.eeprom = bytearray(rnd.randrange(256) for _ in p.eeprom)
        self.modelo = modelo
        self.serie = serie
        self.bloquear_eeprom = bloquear_eeprom
        self.ignorar_escrita = ignorar_escrita
        self.perda = perda
        self.liberada_temp = False
        self.escritas = []
        self.lock = threading.Lock()
        # valores "realistas"
        self.eeprom[0x18], self.eeprom[0x19] = contador & 0xFF, contador >> 8
        self.eeprom[0x1C], self.eeprom[0x1D] = contador & 0xFF, contador >> 8
        self.eeprom[0x1E] = 0
        self.eeprom[0x2E] = 0x5E
        for i, c in enumerate(serie.encode()):
            self.eeprom[0xC0 + i] = c
        self.eeprom[0xA4:0xA8] = (12345).to_bytes(4, "little")
        self.eeprom[0xA8:0xAC] = (98765).to_bytes(4, "little")
        self.eeprom[0x1D4:0x1D8] = (210).to_bytes(4, "little")
        self.eeprom[0x93], self.eeprom[0x94], self.eeprom[0x95] = 7, 31, 4

    @property
    def contador(self):
        return self.eeprom[0x18] | (self.eeprom[0x19] << 8)

    # ---- comandos EPSON-CTRL --------------------------------------------------

    def _ctrl(self, bruto):
        cmd, n = bruto[:2], struct.unpack("<H", bruto[2:4])[0]
        payload = bruto[4:4 + n]
        if len(payload) != n:
            return None
        if cmd == b"vi":
            return b"\x00@BDC PS\r\nvi:00:RF20H5;\x0c"
        if cmd == b"st":
            erro = self.contador >= PerfilL395.contador_max and not self.liberada_temp
            corpo = bytes([0x01, 1, 0x00 if erro else 0x04])
            if erro:
                corpo += bytes([0x02, 1, 0x10])
            corpo += bytes([0x40, len(self.serie)]) + self.serie.encode()
            return b"\x00@BDC ST2\r\n" + struct.pack("<H", len(corpo)) + corpo + b"\x0c"
        if cmd == b"rw":
            ok = payload[2:] == hashlib.sha1(self.serie.encode()).digest() and payload[0] == 1
            if ok:
                self.liberada_temp = True
            return b"\x00@BDC PS\r\nrw:01:%s;\x0c" % (b"OK" if ok else b"NA")
        if cmd == b"||":
            acao = payload[2] if len(payload) > 2 else 0
            chave_ok = payload[:2] == PerfilL395.chave_leitura and not self.bloquear_eeprom
            if acao == 0x41 and n == 7:
                end = struct.unpack("<H", payload[5:7])[0]
                if not chave_ok or end >= len(self.eeprom):
                    return b"\x00@BDC PS\r\n||:41:NA;\x0c"
                return b"\x00@BDC PS\r\nEE:%04X%02X;\x0c" % (end, self.eeprom[end])
            if acao == 0x42 and n == 16:
                end = struct.unpack("<H", payload[5:7])[0]
                valor = payload[7]
                chave = payload[8:16]
                if not chave_ok or chave != _chave_escrita(PerfilL395.chave_escrita):
                    return b"\x00@BDC PS\r\n||:42:NA;\x0c"
                if not self.ignorar_escrita:
                    self.eeprom[end] = valor
                    self.escritas.append((end, valor))
                return b"\x00@BDC PS\r\n||:42:OK;\x0c"
            return b"\x00@BDC PS\r\n||:NA;\x0c"
        return None

    def responder(self, partes):
        """Retorna (erro_snmp, tag, valor) para um OID."""
        oid = ".".join(map(str, partes))
        if oid in OIDS_TEXTO:
            return 0, 0x04, OIDS_TEXTO[oid] or self.modelo
        if partes[:len(PREFIXO_CTRL)] == PREFIXO_CTRL:
            bruto = partes[len(PREFIXO_CTRL):]
            if all(0 <= b <= 255 for b in bruto) and len(bruto) >= 4:
                with self.lock:
                    r = self._ctrl(bytes(bruto))
                if r is not None:
                    return 0, 0x04, r
        return 2, 0x05, b""  # noSuchName

    # ---- transporte SNMP --------------------------------------------------------

    def tratar_pacote(self, dados):
        tag, corpo, _ = _ler_tlv(dados, 0)
        versao, comunidade, (tag_pdu, pdu) = _filhos(corpo)
        if tag_pdu != 0xA0:
            return None
        campos = _filhos(pdu)
        req_id = int.from_bytes(campos[0][1], "big", signed=True)
        vb = _filhos(_filhos(campos[3][1])[0][1])
        partes = _decodificar_oid(vb[0][1])
        erro, tag_v, valor = self.responder(partes)
        varbind = _tlv(0x30, _oid_ber(partes) + _tlv(tag_v, valor))
        resp = _tlv(0xA2, _ber_int(req_id) + _ber_int(erro) + _ber_int(1 if erro else 0)
                    + _tlv(0x30, varbind))
        return _tlv(0x30, _ber_int(0) + _tlv(0x04, comunidade[1]) + resp)

    def servir(self, sock, parar):
        sock.settimeout(0.2)
        while not parar.is_set():
            try:
                dados, origem = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if self.perda and random.random() < self.perda:
                continue
            try:
                resp = self.tratar_pacote(dados)
            except Exception:
                continue
            if resp:
                sock.sendto(resp, origem)


def iniciar_em_thread(sim, host="127.0.0.1", porta=0):
    """Sobe o simulador numa thread. Retorna (porta, função_parar)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, porta))
    parar = threading.Event()
    t = threading.Thread(target=sim.servir, args=(sock, parar), daemon=True)
    t.start()

    def finalizar():
        parar.set()
        t.join(2)
        sock.close()

    return sock.getsockname()[1], finalizar


def main():
    ap = argparse.ArgumentParser(description="Simulador de Epson L395 (SNMP)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--porta", type=int, default=16100)
    ap.add_argument("--contador", type=int, default=6207, help="valor inicial (6207 = 100%%)")
    ap.add_argument("--bloquear-eeprom", action="store_true", help="simula firmware bloqueado")
    ap.add_argument("--ignorar-escrita", action="store_true",
                    help="responde OK mas não grava (firmware 'mentiroso')")
    ap.add_argument("--perda", type=float, default=0.0, help="fração de pacotes perdidos (0-1)")
    a = ap.parse_args()
    sim = L395Simulada(contador=a.contador, bloquear_eeprom=a.bloquear_eeprom,
                       ignorar_escrita=a.ignorar_escrita, perda=a.perda)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((a.host, a.porta))
    print("L395 simulada em %s:%d (Ctrl+C para sair)" % (a.host, a.porta))
    try:
        sim.servir(sock, threading.Event())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

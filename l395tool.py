#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
l395tool — manutenção da Epson L395 sem software de terceiros.

Fala com a impressora pela rede (Wi-Fi), via SNMP v1, usando os comandos
EPSON-CTRL ("Remote Mode") que o próprio firmware expõe. Não precisa de
driver, instalação nem bibliotecas externas: só Python 3.8+.

Uso rápido:
    python l395tool.py procurar
    python l395tool.py info 192.168.0.50
    python l395tool.py zerar 192.168.0.50

Parâmetros da L395 conferidos em dois projetos open source independentes:
  - epson_print_conf (github.com/Ircama/epson_print_conf) — perfil ET-2600 / L395
  - ez-reset         (github.com/CiRIP/ez-reset)          — devices.xml, <L395>
"""

import argparse
import datetime as dt
import hashlib
import json
import random
import re
import socket
import struct
import sys
import time
from pathlib import Path

VERSAO = "1.0"


# =============================================================================
# Perfil da impressora
# =============================================================================

class PerfilL395:
    """Endereços e chaves da EEPROM da L395 (mesma placa da ET-2600)."""

    nome = "Epson L395"
    modelos_aceitos = ("L395", "ET-2600")

    # Chave de leitura ("R code" / "factory") e chave de escrita ("keyword").
    chave_leitura = bytes([0x10, 0x08])
    chave_escrita = b"Sinabung"      # vai para a impressora com cada byte +1

    # Contador de tinta residual (almofadas): 16 bits little-endian.
    contador = (0x18, 0x19)          # LSB, MSB
    contador_aux = 0x1E              # byte auxiliar, normalmente 0
    contador_max = 6207              # valor que a Epson considera 100%

    # Sequência de reset (idêntica nas duas fontes):
    #   0x18, 0x19, 0x1E -> contador principal
    #   0x1C, 0x1D       -> cópia do contador
    #   0x2E = 0x5E (94) -> nível de "manutenção requerida"
    zerar = (
        (0x18, 0x00), (0x19, 0x00), (0x1E, 0x00),
        (0x1C, 0x00), (0x1D, 0x00), (0x2E, 0x5E),
    )

    serie = range(0xC0, 0xCA)        # 10 caracteres ASCII
    eeprom = range(0x000, 0x200)     # 512 bytes

    # Estatísticas (little-endian: o primeiro endereço é o byte menos significativo)
    estatisticas = (
        ("Páginas impressas", (0xA4, 0xA5, 0xA6, 0xA7)),
        ("Passadas de impressão", (0xA8, 0xA9, 0xAA, 0xAB)),
        ("Digitalizações", (0x1D4, 0x1D5, 0x1D6, 0x1D7)),
        ("Limpezas manuais", (0x93,)),
        ("Limpezas ao ligar", (0x94,)),
        ("Limpezas automáticas (timer)", (0x95,)),
    )


# =============================================================================
# SNMP v1 mínimo (BER): só o necessário para GetRequest / GetResponse
# =============================================================================

class SnmpErro(Exception):
    pass


class SemResposta(SnmpErro):
    pass


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, valor):
    return bytes([tag]) + _ber_len(len(valor)) + valor


def _ber_int(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return _tlv(0x02, v.to_bytes(n, "big", signed=True))


def _ber_oid(oid):
    partes = [int(p) for p in oid.strip(".").split(".")]
    if len(partes) < 2:
        raise ValueError("OID inválido: %s" % oid)
    out = bytearray([40 * partes[0] + partes[1]])
    for p in partes[2:]:
        grupos = [p & 0x7F]
        p >>= 7
        while p:
            grupos.append(0x80 | (p & 0x7F))
            p >>= 7
        out.extend(reversed(grupos))
    return _tlv(0x06, bytes(out))


def montar_get(comunidade, req_id, oid):
    """Monta um GetRequest SNMP v1 com um único OID."""
    varbind = _tlv(0x30, _ber_oid(oid) + b"\x05\x00")
    pdu = _tlv(0xA0, _ber_int(req_id) + _ber_int(0) + _ber_int(0) + _tlv(0x30, varbind))
    return _tlv(0x30, _ber_int(0) + _tlv(0x04, comunidade.encode()) + pdu)


def _ler_tlv(buf, pos):
    if pos + 2 > len(buf):
        raise ValueError("pacote truncado")
    tag = buf[pos]
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        raise ValueError("pacote truncado")
    return tag, buf[pos:pos + n], pos + n


def _filhos(buf):
    pos, itens = 0, []
    while pos < len(buf):
        tag, valor, pos = _ler_tlv(buf, pos)
        itens.append((tag, valor))
    return itens


def ler_resposta(pacote):
    """Decodifica um GetResponse. Retorna (req_id, erro, índice, (tag, valor))."""
    tag, corpo, _ = _ler_tlv(pacote, 0)
    if tag != 0x30:
        raise ValueError("não é uma mensagem SNMP")
    itens = _filhos(corpo)
    if len(itens) != 3 or itens[2][0] != 0xA2:
        raise ValueError("não é um GetResponse")
    pdu = _filhos(itens[2][1])
    req_id = int.from_bytes(pdu[0][1], "big", signed=True)
    erro = int.from_bytes(pdu[1][1], "big", signed=True)
    indice = int.from_bytes(pdu[2][1], "big", signed=True)
    varbinds = _filhos(pdu[3][1])
    valor = (0x05, b"")
    if varbinds:
        vb = _filhos(varbinds[0][1])
        if len(vb) == 2:
            valor = vb[1]
    return req_id, erro, indice, valor


class Snmp:
    def __init__(self, host, comunidade="public", porta=161, timeout=2.0,
                 tentativas=3, debug=False):
        self.host = host
        self.porta = porta
        self.comunidade = comunidade
        self.timeout = timeout
        self.tentativas = tentativas
        self.debug = debug
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def fechar(self):
        self.sock.close()

    def get(self, oid):
        """GET de um OID. Retorna bytes (OCTET STRING), int ou None."""
        req_id = random.randint(1, 0x7FFFFFFF)
        pacote = montar_get(self.comunidade, req_id, oid)
        if self.debug:
            sys.stderr.write("> GET %s\n" % oid)
        for _ in range(self.tentativas):
            try:
                self.sock.sendto(pacote, (self.host, self.porta))
            except OSError as e:
                raise SnmpErro("falha ao enviar para %s: %s" % (self.host, e))
            limite = time.monotonic() + self.timeout
            while True:
                resta = limite - time.monotonic()
                if resta <= 0:
                    break
                self.sock.settimeout(resta)
                try:
                    dados, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    break
                except OSError:  # p.ex. WSAECONNRESET no Windows
                    break
                try:
                    rid, erro, _, (tag, valor) = ler_resposta(dados)
                except (ValueError, IndexError):
                    continue
                if rid != req_id:
                    continue  # resposta atrasada de um pedido anterior
                if self.debug:
                    sys.stderr.write("< erro=%d tag=0x%02X %r\n" % (erro, tag, bytes(valor)))
                if erro:
                    raise SnmpErro("a impressora respondeu com erro SNMP %d" % erro)
                if tag == 0x04:
                    return bytes(valor)
                if tag in (0x02, 0x41, 0x42, 0x43):
                    return int.from_bytes(valor, "big")
                return None
        raise SemResposta("sem resposta de %s:%d" % (self.host, self.porta))


# =============================================================================
# Protocolo Epson (EPSON-CTRL sobre SNMP)
# =============================================================================

OID_EPSON_CTRL = "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1"
OID_HR_DEVICE_DESCR = "1.3.6.1.2.1.25.3.2.1.3.1"
OID_EPSON_MODELO = "1.3.6.1.4.1.1248.1.2.2.1.1.1.2.1"
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"

STATUS = {
    0x00: "Erro", 0x01: "Imprimindo página interna", 0x02: "Ocupada",
    0x03: "Aguardando", 0x04: "Pronta", 0x05: "Pausada", 0x07: "Limpando a cabeça",
    0x0A: "Desligando", 0x0F: "Teste de jatos", 0x11: "Carregando tinta",
}
ERROS = {
    0x00: "erro fatal", 0x02: "tampa aberta", 0x04: "papel atolado",
    0x05: "sem tinta", 0x06: "sem papel",
    0x10: "almofadas de tinta no limite (contador estourado)",
    0x41: "pedido de manutenção", 0x47: "impressão desabilitada",
}


class AcessoNegado(Exception):
    pass


class EscritaFalhou(Exception):
    pass


def ctrl_oid(cmd, payload):
    """Converte um comando EPSON-CTRL em OID: cmd(2) + tamanho(2, LE) + payload."""
    bruto = cmd + struct.pack("<H", len(payload)) + payload
    return OID_EPSON_CTRL + "." + ".".join(str(b) for b in bruto)


def _acao(a):
    """Código de ação da EEPROM: a, NOT a, rotação de a (ex.: 'A' -> 41 BE A0)."""
    return bytes([a, a ^ 0xFF, ((a >> 1) & 0x7F) | ((a << 7) & 0x80)])


def _chave_escrita(chave):
    return bytes(0 if b == 0 else b + 1 for b in chave)


def oid_ler_eeprom(perfil, endereco):
    return ctrl_oid(b"||", perfil.chave_leitura + _acao(0x41) + struct.pack("<H", endereco))


def oid_escrever_eeprom(perfil, endereco, valor):
    payload = (perfil.chave_leitura + _acao(0x42) + struct.pack("<H", endereco)
               + bytes([valor]) + _chave_escrita(perfil.chave_escrita))
    return ctrl_oid(b"||", payload)


def ler_st2(resp):
    """Extrai status, erro e número de série de uma resposta '@BDC ST2'."""
    i = resp.find(b"@BDC ST2\r\n")
    if i < 0:
        return {}
    p = i + 10
    n = int.from_bytes(resp[p:p + 2], "little")
    buf = resp[p + 2:p + 2 + n]
    out, j = {}, 0
    while j + 2 <= len(buf):
        tipo, tam = buf[j], buf[j + 1]
        item = buf[j + 2:j + 2 + tam]
        j += 2 + tam
        if len(item) != tam:
            break
        if tipo == 0x01 and item:
            out["status"] = item[0]
        elif tipo == 0x02 and item:
            out["erro"] = item[0]
        elif tipo == 0x40:
            out["serie"] = item.decode("ascii", "replace").strip("\x00 ")
    return out


class Impressora:
    def __init__(self, snmp, perfil=PerfilL395):
        self.snmp = snmp
        self.perfil = perfil

    # --- comandos básicos ----------------------------------------------------

    def _ctrl(self, oid):
        r = self.snmp.get(oid)
        if not isinstance(r, bytes):
            raise SnmpErro("resposta inesperada: %r" % (r,))
        return r

    def ler(self, endereco):
        r = self._ctrl(oid_ler_eeprom(self.perfil, endereco))
        m = re.search(rb"EE:([0-9A-Fa-f]{4})([0-9A-Fa-f]{2})", r)
        if not m:
            if b":NA;" in r:
                raise AcessoNegado(
                    "a impressora recusou a leitura da EEPROM (chave rejeitada "
                    "ou firmware com acesso bloqueado pela rede)")
            raise SnmpErro("resposta inválida ao ler 0x%03X: %r" % (endereco, r))
        if int(m.group(1), 16) != endereco:
            raise SnmpErro("a impressora devolveu o endereço errado (%s != %03X)"
                           % (m.group(1).decode(), endereco))
        return int(m.group(2), 16)

    def ler_varios(self, enderecos):
        return [self.ler(e) for e in enderecos]

    def escrever(self, endereco, valor):
        """Escreve um byte e confere lendo de volta (o ':OK;' sozinho não basta)."""
        r = self._ctrl(oid_escrever_eeprom(self.perfil, endereco, valor))
        if b":OK;" not in r:
            raise EscritaFalhou("a impressora recusou a escrita em 0x%03X: %r" % (endereco, r))
        lido = self.ler(endereco)
        if lido != valor:
            raise EscritaFalhou(
                "0x%03X ficou com 0x%02X em vez de 0x%02X (a impressora aceitou o "
                "comando, mas não gravou)" % (endereco, lido, valor))

    # --- informações ---------------------------------------------------------

    def modelo(self):
        for oid in (OID_HR_DEVICE_DESCR, OID_EPSON_MODELO, OID_SYS_DESCR):
            try:
                v = self.snmp.get(oid)
            except SemResposta:
                raise
            except SnmpErro:
                continue
            if isinstance(v, bytes) and v.strip(b"\x00 "):
                return v.decode("latin-1").strip("\x00 ")
        return "?"

    def firmware(self):
        try:
            r = self._ctrl(ctrl_oid(b"vi", b"\x00"))
        except SnmpErro:
            return None
        m = re.search(rb"vi:00:([^;]{1,32});", r)
        return m.group(1).decode("latin-1") if m else None

    def status(self):
        try:
            return ler_st2(self._ctrl(ctrl_oid(b"st", b"\x01")))
        except SnmpErro:
            return {}

    def serie(self):
        bs = self.ler_varios(self.perfil.serie)
        return "".join(chr(b) if 32 <= b < 127 else "?" for b in bs)

    def contador(self):
        lsb, msb, aux = self.ler_varios(list(self.perfil.contador) + [self.perfil.contador_aux])
        valor = lsb | (msb << 8)
        return valor, 100.0 * valor / self.perfil.contador_max, aux

    def estatisticas(self):
        out = []
        for nome, ends in self.perfil.estatisticas:
            try:
                out.append((nome, int.from_bytes(bytes(self.ler_varios(ends)), "little")))
            except (SnmpErro, AcessoNegado):
                out.append((nome, None))
        return out

    def dump(self, enderecos, progresso=None):
        dados = []
        for i, e in enumerate(enderecos):
            try:
                dados.append(self.ler(e))
            except SemResposta:
                raise
            except (SnmpErro, AcessoNegado):
                dados.append(None)
            if progresso:
                progresso(i + 1, len(enderecos))
        return dados

    def liberar_temporario(self, serie):
        """Comando 'rw' (reset waste): precisa só do SHA-1 do número de série."""
        payload = struct.pack("<H", 1) + hashlib.sha1(serie.encode()).digest()
        r = self._ctrl(ctrl_oid(b"rw", payload))
        return b"rw:" in r and b":OK;" in r, r


# =============================================================================
# Backup em JSON (16 bytes por linha: legível e fácil de comparar)
# =============================================================================

def backup_para_dict(info_impressora, enderecos, dados):
    linhas = {}
    for base in range(enderecos.start - enderecos.start % 16, enderecos.stop, 16):
        cel = []
        for e in range(base, base + 16):
            if e in enderecos:
                v = dados[e - enderecos.start]
                cel.append("??" if v is None else "%02X" % v)
        linhas["%03X" % base] = " ".join(cel)
    return {
        "ferramenta": "l395tool %s" % VERSAO,
        "criado_em": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "impressora": info_impressora,
        "eeprom": linhas,
    }


def backup_de_dict(d):
    valores = {}
    for base_hex, linha in d["eeprom"].items():
        base = int(base_hex, 16)
        for i, cel in enumerate(linha.split()):
            if cel != "??":
                valores[base + i] = int(cel, 16)
    return valores


# =============================================================================
# Interface de linha de comando
# =============================================================================

def _br(n):
    return "{:,}".format(n).replace(",", ".")


def _pct(p):
    return ("%.1f" % p).replace(".", ",") + "%"


def _barra(p, largura=30):
    cheio = max(0, min(largura, int(round(largura * p / 100.0))))
    return "[" + "#" * cheio + "." * (largura - cheio) + "]"


def _progresso(rotulo):
    tty = getattr(sys.stdout, "isatty", lambda: False)()

    def f(i, n):
        if tty and (i % 8 == 0 or i == n):
            sys.stdout.write("\r  %s %s %d/%d" % (rotulo, _barra(100.0 * i / n, 24), i, n))
            sys.stdout.flush()
        if i == n:
            sys.stdout.write("\n" if tty else "  %s %d/%d ok\n" % (rotulo, i, n))
    return f


def _confirmar(args, palavra, texto):
    if args.sim:
        return True
    if not sys.stdin.isatty():
        print("Sem terminal para confirmar. Use --sim para confirmar automaticamente.")
        return False
    if texto:
        print(texto)
    try:
        return input("Digite %s para continuar: " % palavra).strip().upper() == palavra
    except EOFError:
        return False


def _conectar(args):
    snmp = Snmp(args.ip, comunidade=args.comunidade, porta=args.porta,
                timeout=args.timeout, tentativas=args.tentativas, debug=args.debug)
    args.conexao = snmp
    return Impressora(snmp)


def _modelo_ok(imp, modelo):
    return any(m in modelo.upper() for m in imp.perfil.modelos_aceitos)


def _checar_modelo(imp, args):
    modelo = imp.modelo()
    if not _modelo_ok(imp, modelo):
        msg = "A impressora se identificou como %r — não é uma %s." % (modelo, imp.perfil.nome)
        if not args.forcar:
            raise SystemExit(msg + "\nAbortado. (Use --forcar só se tiver certeza.)")
        print("AVISO: " + msg + " Continuando por causa de --forcar.")
    return modelo


def _pasta_backups(args):
    pasta = Path(args.pasta) if args.pasta else Path(__file__).resolve().parent / "backups"
    pasta.mkdir(parents=True, exist_ok=True)
    return pasta


def _fazer_backup(imp, args, modelo, serie, firmware):
    p = imp.perfil
    print("Fazendo backup da EEPROM (%d bytes)..." % len(p.eeprom))
    dados = imp.dump(p.eeprom, _progresso("lendo"))
    falhas = [p.eeprom.start + i for i, v in enumerate(dados) if v is None]
    criticos = [e for e, _ in p.zerar if e in falhas]
    if criticos:
        raise SystemExit("Não consegui ler endereços essenciais (%s). Nada foi alterado."
                         % ", ".join("0x%03X" % e for e in criticos))
    info = {"ip": args.ip, "modelo": modelo, "firmware": firmware, "serie": serie}
    d = backup_para_dict(info, p.eeprom, dados)
    nome = "L395_%s_%s.json" % (re.sub(r"[^A-Za-z0-9]", "", serie) or "semserie",
                               dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
    arq = _pasta_backups(args) / nome
    arq.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Backup salvo em: %s" % arq)
    if falhas:
        print("  (%d endereço(s) não puderam ser lidos e ficaram como ??)" % len(falhas))
    return arq


def cmd_procurar(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    req_id = random.randint(1, 0x7FFFFFFF)
    sock.sendto(montar_get(args.comunidade, req_id, OID_HR_DEVICE_DESCR),
                (args.broadcast, args.porta))
    print("Procurando impressoras em %s (%.0f s)..." % (args.broadcast, args.espera))
    achadas = {}
    limite = time.monotonic() + args.espera
    while True:
        resta = limite - time.monotonic()
        if resta <= 0:
            break
        sock.settimeout(resta)
        try:
            dados, (ip, _) = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            break
        try:
            rid, erro, _, (tag, valor) = ler_resposta(dados)
        except (ValueError, IndexError):
            continue
        if rid == req_id:
            desc = valor.decode("latin-1").strip("\x00 ") if tag == 0x04 else ""
            achadas[ip] = desc or "(dispositivo SNMP sem descrição)"
    sock.close()
    if not achadas:
        print("Nenhuma resposta. Confira se o PC e a impressora estão na mesma rede,\n"
              "ou descubra o IP pelo roteador e use direto: l395tool.py info <IP>")
        return 1
    for ip in sorted(achadas, key=lambda s: tuple(int(x) for x in s.split("."))):
        marca = "   <-- esta" if "L395" in achadas[ip].upper() else ""
        print("  %-15s  %s%s" % (ip, achadas[ip], marca))
    return 0


def cmd_info(args):
    imp = _conectar(args)
    p = imp.perfil
    modelo = imp.modelo()
    print("Impressora   %s" % modelo)
    print("Firmware     %s" % (imp.firmware() or "?"))
    st = imp.status()
    if "status" in st:
        txt = STATUS.get(st["status"], "código %d" % st["status"])
        if "erro" in st and st["status"] == 0:
            txt += " — " + ERROS.get(st["erro"], "código 0x%02X" % st["erro"])
        print("Status       %s" % txt)
    if not _modelo_ok(imp, modelo):
        print("\nAVISO: não parece ser uma %s; os números abaixo podem não fazer sentido."
              % p.nome)
    try:
        print("Nº de série  %s" % imp.serie())
        valor, pct, aux = imp.contador()
    except AcessoNegado as e:
        print("\nEEPROM: %s.\nAlternativa: l395tool.py liberar-temporario %s" % (e, args.ip))
        return 2
    print("\nAlmofadas de tinta (contador da Epson)")
    print("  %s %s  (%s de %s)" % (_barra(pct), _pct(pct), _br(valor), _br(p.contador_max)))
    if aux:
        print("  byte auxiliar 0x%02X = 0x%02X (normalmente 0)" % (p.contador_aux, aux))
    if pct >= 100:
        print("  -> estourado: é isso que bloqueia a impressora.")
    print("\nEstatísticas")
    for nome, v in imp.estatisticas():
        print("  %-30s %s" % (nome, "?" if v is None else _br(v)))
    return 0


def cmd_backup(args):
    imp = _conectar(args)
    modelo = _checar_modelo(imp, args)
    _fazer_backup(imp, args, modelo, imp.serie(), imp.firmware())
    return 0


def cmd_zerar(args):
    imp = _conectar(args)
    p = imp.perfil
    modelo = _checar_modelo(imp, args)
    try:
        serie = imp.serie()
        valor, pct, _ = imp.contador()
    except AcessoNegado as e:
        print("EEPROM: %s.\nAlternativa: l395tool.py liberar-temporario %s" % (e, args.ip))
        return 2
    print("%s  (série %s)" % (modelo, serie))
    print("Contador atual: %s %s (%s de %s)"
          % (_barra(pct), _pct(pct), _br(valor), _br(p.contador_max)))
    print("\nVou gravar na EEPROM:")
    for e, v in p.zerar:
        print("  0x%03X <- 0x%02X" % (e, v))
    if args.simulacao:
        print("\n(--simulacao: nada foi gravado.)")
        return 0
    if not _confirmar(args, "ZERAR",
                      "\nAntes de gravar, a EEPROM inteira será salva num arquivo de backup."):
        print("Cancelado. Nada foi alterado.")
        return 1
    arq = _fazer_backup(imp, args, modelo, serie, imp.firmware())
    print("Gravando...")
    feitos = []
    try:
        for e, v in p.zerar:
            imp.escrever(e, v)
            feitos.append(e)
            print("  0x%03X <- 0x%02X  ok" % (e, v))
    except (EscritaFalhou, SnmpErro, AcessoNegado) as err:
        print("\nFALHOU: %s" % err)
        if feitos:
            print("Endereços já gravados: %s" % ", ".join("0x%03X" % e for e in feitos))
            print("Para desfazer: l395tool.py restaurar %s \"%s\"" % (args.ip, arq))
        else:
            print("Nada foi alterado.")
        print("Se o firmware bloqueia escrita pela rede, tente: "
              "l395tool.py liberar-temporario %s" % args.ip)
        return 3
    valor, pct, _ = imp.contador()
    print("\nContador agora: %s %s" % (_barra(pct), _pct(pct)))
    print("Pronto. Desligue a impressora no botão, espere uns 10 s e ligue de novo.")
    print("Backup (para desfazer): %s" % arq)
    return 0


def cmd_restaurar(args):
    imp = _conectar(args)
    modelo = _checar_modelo(imp, args)
    d = json.loads(Path(args.arquivo).read_text(encoding="utf-8"))
    valores = backup_de_dict(d)
    serie_bkp = (d.get("impressora") or {}).get("serie")
    serie = imp.serie()
    if serie_bkp and serie_bkp != serie:
        msg = "O backup é da impressora de série %s, mas esta é a %s." % (serie_bkp, serie)
        if not args.forcar:
            raise SystemExit(msg + " Abortado. (Use --forcar só se tiver certeza.)")
        print("AVISO: " + msg)
    if args.tudo:
        alvo = sorted(valores)
    else:
        alvo = [e for e, _ in imp.perfil.zerar if e in valores]
    print("%s  (série %s)\nComparando com o backup de %s..."
          % (modelo, serie, d.get("criado_em", "?")))
    atuais = imp.dump(alvo, _progresso("lendo") if len(alvo) > 20 else None)
    mudar = [(e, a, valores[e]) for e, a in zip(alvo, atuais) if a != valores[e]]
    if not mudar:
        print("Nada a fazer: a impressora já tem os valores do backup.")
        return 0
    print("\n%d byte(s) diferente(s):" % len(mudar))
    for e, a, v in mudar[:40]:
        print("  0x%03X  %s -> %02X" % (e, "??" if a is None else "%02X" % a, v))
    if len(mudar) > 40:
        print("  ... e mais %d" % (len(mudar) - 40))
    if not _confirmar(args, "RESTAURAR", ""):
        print("Cancelado. Nada foi alterado.")
        return 1
    for i, (e, _, v) in enumerate(mudar):
        try:
            imp.escrever(e, v)
        except (EscritaFalhou, SnmpErro, AcessoNegado) as err:
            print("\nFALHOU em 0x%03X: %s (%d de %d gravados)" % (e, err, i, len(mudar)))
            return 3
    print("Restaurado (%d byte(s)). Desligue e ligue a impressora." % len(mudar))
    return 0


def cmd_ler(args):
    imp = _conectar(args)
    for txt in args.enderecos:
        e = int(txt, 0)
        try:
            v = imp.ler(e)
            print("0x%03X = 0x%02X  (%d)" % (e, v, v))
        except AcessoNegado as err:
            print("0x%03X : %s" % (e, err))
            return 2
    return 0


def cmd_liberar_temporario(args):
    imp = _conectar(args)
    _checar_modelo(imp, args)
    serie = imp.status().get("serie")
    if not serie:
        try:
            serie = imp.serie()
        except AcessoNegado:
            serie = None
    if not serie or "?" in serie:
        print("Não consegui obter o número de série da impressora.")
        return 2
    print("Série: %s. Enviando o comando de liberação temporária (rw)..." % serie)
    ok, resp = imp.liberar_temporario(serie)
    if ok:
        print("Aceito. Desligue e ligue a impressora. (Isto não zera a EEPROM: o\n"
              "contador continua lá, e o bloqueio pode voltar mais adiante.)")
        return 0
    print("A impressora não confirmou: %r" % resp)
    return 3


def main(argv=None):
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

    comum = argparse.ArgumentParser(add_help=False)
    comum.add_argument("--comunidade", default="public", help="comunidade SNMP (padrão: public)")
    comum.add_argument("--porta", type=int, default=161, help=argparse.SUPPRESS)
    comum.add_argument("--timeout", type=float, default=2.0, help="segundos por tentativa")
    comum.add_argument("--tentativas", type=int, default=3)
    comum.add_argument("--debug", action="store_true", help="mostra os pacotes trocados")

    com_ip = argparse.ArgumentParser(add_help=False, parents=[comum])
    com_ip.add_argument("ip", help="IP da impressora (ex.: 192.168.0.50)")
    com_ip.add_argument("--forcar", action="store_true",
                        help="ignora a checagem de modelo / número de série")
    com_ip.add_argument("--sim", action="store_true", help="não pede confirmação")
    com_ip.add_argument("--pasta", help="pasta dos backups (padrão: ./backups)")

    ap = argparse.ArgumentParser(
        prog="l395tool",
        description="Manutenção da Epson L395 pela rede (SNMP). v" + VERSAO)
    sub = ap.add_subparsers(dest="comando", required=True)

    s = sub.add_parser("procurar", parents=[comum], help="acha impressoras na rede local")
    s.add_argument("--broadcast", default="255.255.255.255")
    s.add_argument("--espera", type=float, default=3.0)
    s.set_defaults(func=cmd_procurar)

    sub.add_parser("info", parents=[com_ip], help="modelo, status e contador das almofadas"
                   ).set_defaults(func=cmd_info)
    sub.add_parser("backup", parents=[com_ip], help="salva a EEPROM inteira em .json"
                   ).set_defaults(func=cmd_backup)

    s = sub.add_parser("zerar", parents=[com_ip], help="backup + zera o contador das almofadas")
    s.add_argument("--simulacao", action="store_true", help="só mostra o que faria")
    s.set_defaults(func=cmd_zerar)

    s = sub.add_parser("restaurar", parents=[com_ip], help="devolve valores de um backup")
    s.add_argument("arquivo")
    s.add_argument("--tudo", action="store_true",
                   help="restaura a EEPROM inteira (padrão: só os bytes do contador)")
    s.set_defaults(func=cmd_restaurar)

    s = sub.add_parser("ler", parents=[com_ip], help="lê bytes da EEPROM (ex.: 0x18 0x19)")
    s.add_argument("enderecos", nargs="+")
    s.set_defaults(func=cmd_ler)

    sub.add_parser("liberar-temporario", parents=[com_ip],
                   help="comando 'rw' da Epson; alternativa se a EEPROM estiver bloqueada"
                   ).set_defaults(func=cmd_liberar_temporario)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except SemResposta:
        print("\nA impressora não respondeu em %s.\n"
              "Confira: ligada, conectada ao Wi-Fi, na mesma rede do computador e IP correto."
              % getattr(args, "ip", "?"))
        return 4
    except SnmpErro as e:
        print("\nErro de comunicação: %s" % e)
        return 4
    except KeyboardInterrupt:
        print("\nInterrompido.")
        return 130
    finally:
        if getattr(args, "conexao", None):
            args.conexao.fechar()


if __name__ == "__main__":
    sys.exit(main())

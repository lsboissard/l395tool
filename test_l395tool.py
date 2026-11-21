#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Testes do l395tool contra o simulador. Rode: python -m unittest -v test_l395tool"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import l395tool as t
from simulador_l395 import L395Simulada, iniciar_em_thread


class PerfilExemplo(t.PerfilL395):
    chave_leitura = bytes([25, 7])
    chave_escrita = b"Wakatobi"


class PerfilExemplo2(t.PerfilL395):
    chave_leitura = bytes([0x49, 0x08])
    chave_escrita = b"Arantifo"


class TestProtocolo(unittest.TestCase):
    """Confere os comandos gerados contra exemplos publicados por terceiros."""

    def test_leitura_igual_ao_exemplo_do_epson_print_conf(self):
        self.assertEqual(
            t.oid_ler_eeprom(PerfilExemplo, 173),
            "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.7.0.25.7.65.190.160.173.0")

    def test_escrita_igual_ao_exemplo_do_epson_print_conf(self):
        self.assertEqual(
            t.oid_escrever_eeprom(PerfilExemplo, 173, 25),
            "1.3.6.1.4.1.1248.1.2.2.44.1.1.2.1.124.124.16.0.25.7.66.189.33.173.0.25."
            "88.98.108.98.117.112.99.106")

    def test_escrita_hex_igual_ao_exemplo_do_readme(self):
        oid = t.oid_escrever_eeprom(PerfilExemplo2, 0x30, 0x1A)
        bruto = bytes(int(x) for x in oid[len(t.OID_EPSON_CTRL) + 1:].split("."))
        self.assertEqual(bruto.hex(" ").upper(),
                         "7C 7C 10 00 49 08 42 BD 21 30 00 1A 42 73 62 6F 75 6A 67 70")

    def test_chave_da_l395_igual_ao_ez_reset(self):
        # devices.xml do ez-reset, <L395><service><keyword>
        self.assertEqual(t._chave_escrita(t.PerfilL395.chave_escrita),
                         bytes([0x54, 0x6A, 0x6F, 0x62, 0x63, 0x76, 0x6F, 0x68]))

    def test_ber_round_trip(self):
        pkt = t.montar_get("public", 123456, t.oid_ler_eeprom(t.PerfilL395, 0x1D4))
        tag, corpo, fim = t._ler_tlv(pkt, 0)
        self.assertEqual((tag, fim), (0x30, len(pkt)))


class ComSimulador(unittest.TestCase):
    sim_kwargs = {}

    def setUp(self):
        self.sim = L395Simulada(**self.sim_kwargs)
        self.porta, self._parar = iniciar_em_thread(self.sim)
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._parar()
        self.tmp.cleanup()

    def rodar(self, *args):
        argv = list(args) + ["--porta", str(self.porta), "--timeout", "0.3"]
        if args[0] != "procurar":
            argv += ["--pasta", self.tmp.name]
        saida = io.StringIO()
        with contextlib.redirect_stdout(saida):
            try:
                cod = t.main(argv)
            except SystemExit as e:
                cod = e.code
        return cod, saida.getvalue()

    def backups(self):
        return sorted(Path(self.tmp.name).glob("*.json"))


class TestFluxoNormal(ComSimulador):

    def test_info(self):
        cod, out = self.rodar("info", "127.0.0.1")
        self.assertEqual(cod, 0, out)
        for trecho in ("EPSON L395 Series", "RF20H5", "X4HK012345", "100,0%",
                       "6.207 de 6.207", "almofadas de tinta no limite", "12.345"):
            self.assertIn(trecho, out)

    def test_backup_bate_byte_a_byte(self):
        cod, out = self.rodar("backup", "127.0.0.1")
        self.assertEqual(cod, 0, out)
        (arq,) = self.backups()
        valores = t.backup_de_dict(json.loads(arq.read_text(encoding="utf-8")))
        self.assertEqual(len(valores), 512)
        self.assertEqual(bytes(valores[i] for i in range(512)), bytes(self.sim.eeprom))

    def test_simulacao_nao_grava(self):
        antes = bytes(self.sim.eeprom)
        cod, out = self.rodar("zerar", "127.0.0.1", "--simulacao")
        self.assertEqual(cod, 0, out)
        self.assertEqual(bytes(self.sim.eeprom), antes)
        self.assertEqual(self.backups(), [])

    def test_zerar_e_restaurar(self):
        original = bytes(self.sim.eeprom)
        cod, out = self.rodar("zerar", "127.0.0.1", "--sim")
        self.assertEqual(cod, 0, out)
        self.assertEqual(self.sim.contador, 0)
        self.assertEqual(self.sim.escritas, list(t.PerfilL395.zerar))
        alterados = {i for i in range(512) if self.sim.eeprom[i] != original[i]}
        self.assertTrue(alterados <= {e for e, _ in t.PerfilL395.zerar}, alterados)
        cod, out = self.rodar("info", "127.0.0.1")
        self.assertIn("Pronta", out)
        self.assertIn("0,0%", out)

        (arq,) = self.backups()
        cod, out = self.rodar("restaurar", "127.0.0.1", str(arq), "--sim")
        self.assertEqual(cod, 0, out)
        self.assertEqual(bytes(self.sim.eeprom), original)

    def test_ler(self):
        cod, out = self.rodar("ler", "127.0.0.1", "0x18", "0x19", "46")
        self.assertEqual(cod, 0, out)
        self.assertIn("0x018 = 0x3F", out)
        self.assertIn("0x019 = 0x18", out)
        self.assertIn("0x02E = 0x5E", out)

    def test_procurar(self):
        cod, out = self.rodar("procurar", "--broadcast", "127.0.0.1", "--espera", "0.5")
        self.assertEqual(cod, 0, out)
        self.assertIn("EPSON L395 Series", out)

    def test_sem_resposta(self):
        self._parar()
        cod, out = self.rodar("info", "127.0.0.1", "--tentativas", "1")
        self.assertEqual(cod, 4)
        self.assertIn("não respondeu", out)

    def test_backup_de_outra_impressora_e_recusado(self):
        self.rodar("backup", "127.0.0.1")
        (arq,) = self.backups()
        d = json.loads(arq.read_text(encoding="utf-8"))
        d["impressora"]["serie"] = "OUTRA00000"
        arq.write_text(json.dumps(d), encoding="utf-8")
        antes = bytes(self.sim.eeprom)
        cod, out = self.rodar("restaurar", "127.0.0.1", str(arq), "--sim", "--tudo")
        self.assertNotEqual(cod, 0)
        self.assertEqual(bytes(self.sim.eeprom), antes)


class TestOutroModelo(ComSimulador):
    sim_kwargs = {"modelo": b"EPSON L3150 Series"}

    def test_recusa_zerar(self):
        antes = bytes(self.sim.eeprom)
        cod, out = self.rodar("zerar", "127.0.0.1", "--sim")
        self.assertNotEqual(cod, 0)
        self.assertEqual(bytes(self.sim.eeprom), antes)


class TestFirmwareBloqueado(ComSimulador):
    sim_kwargs = {"bloquear_eeprom": True}

    def test_info_explica_e_sugere_alternativa(self):
        cod, out = self.rodar("info", "127.0.0.1")
        self.assertEqual(cod, 2)
        self.assertIn("recusou a leitura", out)
        self.assertIn("liberar-temporario", out)

    def test_liberar_temporario(self):
        cod, out = self.rodar("liberar-temporario", "127.0.0.1")
        self.assertEqual(cod, 0, out)
        self.assertTrue(self.sim.liberada_temp)


class TestFirmwareQueMenteNaEscrita(ComSimulador):
    sim_kwargs = {"ignorar_escrita": True}

    def test_detecta_escrita_nao_gravada(self):
        cod, out = self.rodar("zerar", "127.0.0.1", "--sim")
        self.assertEqual(cod, 3)
        self.assertIn("não gravou", out)
        self.assertIn("Nada foi alterado", out)


class TestRedeRuim(ComSimulador):
    sim_kwargs = {"perda": 0.25}

    def test_zerar_com_perda_de_pacotes(self):
        rodar = self.rodar

        def rodar_com_mais_tentativas(*a):
            return rodar(*a, "--tentativas", "12")
        cod, out = rodar_com_mais_tentativas("zerar", "127.0.0.1", "--sim")
        self.assertEqual(cod, 0, out)
        self.assertEqual(self.sim.contador, 0)


try:
    from pysnmp.proto import api as _pysnmp_api
    from pyasn1.codec.ber import decoder as _dec, encoder as _enc
except Exception:  # pysnmp é opcional: só serve para conferência independente
    _pysnmp_api = None


@unittest.skipIf(_pysnmp_api is None, "pysnmp não instalado")
class TestContraPysnmp(ComSimulador):
    """Usa a biblioteca pysnmp como 'juiz' independente da codificação BER."""

    def test_pysnmp_entende_o_get_do_l395tool(self):
        p = _pysnmp_api.PROTOCOL_MODULES[_pysnmp_api.SNMP_VERSION_1]
        oid = t.oid_escrever_eeprom(t.PerfilL395, 0x1D4, 0xAB)
        msg, _ = _dec.decode(t.montar_get("public", 987654, oid), asn1Spec=p.Message())
        pdu = p.apiMessage.get_pdu(msg)
        self.assertEqual(int(p.apiPDU.get_request_id(pdu)), 987654)
        (nome, _), = p.apiPDU.get_varbinds(pdu)
        self.assertEqual(str(nome), oid)

    def test_l395tool_entende_resposta_do_pysnmp(self):
        p = _pysnmp_api.PROTOCOL_MODULES[_pysnmp_api.SNMP_VERSION_1]
        oid = t.oid_ler_eeprom(t.PerfilL395, 0x18)
        resp_pdu = p.GetResponsePDU()
        p.apiPDU.set_defaults(resp_pdu)
        p.apiPDU.set_request_id(resp_pdu, 4242)
        p.apiPDU.set_varbinds(resp_pdu, [(oid, p.OctetString(b"\x00@BDC PS\r\nEE:00183F;\x0c"))])
        msg = p.Message()
        p.apiMessage.set_defaults(msg)
        p.apiMessage.set_community(msg, "public")
        p.apiMessage.set_pdu(msg, resp_pdu)
        rid, erro, _, (tag, valor) = t.ler_resposta(_enc.encode(msg))
        self.assertEqual((rid, erro, tag), (4242, 0, 0x04))
        self.assertIn(b"EE:00183F;", valor)


if __name__ == "__main__":
    unittest.main(verbosity=2)

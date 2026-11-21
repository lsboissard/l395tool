# l395tool

Utilitário próprio para zerar o contador das almofadas de tinta da **Epson L395**.

- Conversa com a impressora **pela rede (Wi-Fi)**, via SNMP, usando os comandos de
  manutenção que o próprio firmware da Epson aceita. Não instala driver, não precisa de USB.
- **Sempre faz backup da EEPROM inteira** antes de gravar, e confere cada byte gravado
  lendo de volta.

## O que ele grava

| Endereço | Valor | O que é |
|---|---|---|
| 0x18, 0x19, 0x1E | 00 | contador das almofadas (100% = 6207) |
| 0x1C, 0x1D | 00 | cópia do contador |
| 0x2E | 5E | nível de "manutenção requerida" |

Créditos:
([epson_print_conf](https://github.com/Ircama/epson_print_conf) e
[ez-reset](https://github.com/CiRIP/ez-reset))

## Como usar

Com a impressora ligada e no mesmo Wi-Fi do computador:

```
python l395tool.py procurar                  # descobre o IP
python l395tool.py info 192.168.0.50         # mostra modelo, status e % das almofadas
python l395tool.py zerar 192.168.0.50 --simulacao   # mostra o que faria, sem gravar
python l395tool.py zerar 192.168.0.50        # backup + zera (pede para digitar ZERAR)
```

Depois de zerar: desligue a impressora no botão, espere uns 10 s e ligue de novo.

Outros comandos:

```
python l395tool.py backup 192.168.0.50                       # só o backup
python l395tool.py restaurar 192.168.0.50 backups\L395_....json   # desfaz o reset
python l395tool.py restaurar 192.168.0.50 backups\L395_....json --tudo  # EEPROM inteira
python l395tool.py ler 192.168.0.50 0x18 0x19                # lê bytes soltos
python l395tool.py liberar-temporario 192.168.0.50           # plano B (ver abaixo)
```

Qualquer comando aceita `--debug`, que mostra cada pacote trocado com a impressora.

Os backups ficam na pasta `backups/`, ao lado do script, em JSON legível
(16 bytes por linha). Guarde o primeiro: ele é a "foto" da sua impressora antes de tudo.

## Se algo não funcionar

- **"A impressora não respondeu"**: confira o IP, se a impressora está no Wi-Fi (luz
  de Wi-Fi acesa) e se o PC está na mesma rede (rede de convidados costuma isolar).
  Se você só usa a L395 por USB, basta conectá-la ao Wi-Fi para fazer o reset.
- **"recusou a leitura da EEPROM"**: algumas atualizações de firmware da Epson bloqueiam
  esse acesso pela rede. Nesse caso use `liberar-temporario`: é um comando separado
  (`rw`) que destrava sem mexer na EEPROM, mas o bloqueio pode voltar depois.
- **"a impressora aceitou o comando, mas não gravou"**: mesmo motivo (firmware que
  ignora a escrita). Nada foi alterado; use `liberar-temporario`.

## Sobre as almofadas

O contador é uma estimativa da Epson, não um sensor: ele não sabe se a almofada está
seca ou encharcada. Se esta já é a segunda ou terceira vez que você zera, vale olhar
embaixo da impressora (mancha de tinta = almofada saturada). A solução definitiva usada
por muita gente com as L-series é um **reservatório externo de tinta residual**: o tubo de
descarte é levado para um frasco fora da impressora.

## Testes

`simulador_l395.py` é uma L395 de mentira na rede (responde como a real, inclusive
recusando chave errada, simulando firmware bloqueado, perda de pacotes etc.).

```
python -m unittest -v test_l395tool
```

20 testes: confere os comandos gerados contra exemplos publicados por terceiros e
roda todos os fluxos (info, backup, zerar, restaurar, firmware bloqueado, escrita
ignorada, rede ruim). Se o `pysnmp` estiver instalado, ele também é usado como juiz
independente da codificação SNMP.

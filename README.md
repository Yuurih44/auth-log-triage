# Auth Log Triage

Ferramenta defensiva de linha de comando para resumir eventos de autenticação e sinalizar falhas repetidas por IP em uma janela de tempo. Processa arquivos locais e funciona sem serviços externos ou dependências de terceiros.

Projeto educacional preparado com assistência do Codex. O objetivo é praticar parsing, validação, correlação temporal, testes e documentação de regras de detecção.

## Executar

Requer Python 3.10 ou superior. Na pasta do projeto:

```sh
python triage.py examples/auth.jsonl
python triage.py examples/auth.jsonl --threshold 3 --window-seconds 120
python -m unittest -v
```

No Linux, use `python3` se necessário. O relatório JSON é escrito na saída padrão; redirecione para um arquivo para salvá-lo.

## Entrada

Um objeto JSON por linha, com timestamp ISO 8601 com fuso, IP de origem IPv4/IPv6 e resultado `success` ou `failure`:

```json
{"timestamp":"2026-01-01T10:00:00Z","source_ip":"192.0.2.10","outcome":"failure"}
```

Os exemplos são sintéticos. Campos extras são descartados. Registros inválidos são ignorados, e seus números de linha aparecem no relatório. Linhas em branco não são eventos. Não há parser direto de logs SSH, Windows Event Log ou Apache: esses formatos precisam ser convertidos para o esquema acima.

## Regra e resultado

Por padrão, a regra sinaliza pelo menos cinco falhas do mesmo IP em até 300 segundos, incluindo os limites da janela. Eventos são ordenados por horário; sucessos não contam como falhas e não apagam falhas anteriores. IPs IPv6 equivalentes são normalizados.

O relatório traz totais, linhas inválidas, configuração e uma evidência por IP: a primeira janela que alcança o limite. O exemplo fornecido produz seis eventos válidos, cinco falhas, um sucesso e uma ocorrência para `192.0.2.10`.

Código de saída 0 significa que o arquivo foi processado, mesmo com linhas inválidas ou ocorrências. Código 2 indica erro de leitura ou configuração.

## Interpretação e limites

Uma ocorrência é um sinal para investigar, não comprovação de ataque ou invasão. NAT, automações e erros de configuração podem gerar falhas legítimas. A regra não identifica pessoas nem detecta tentativas distribuídas abaixo do limite por IP.

O programa é offline, não bloqueia endereços e não monitora eventos em tempo real. Guarda timestamps de falha em memória, portanto não foi dimensionado para arquivos grandes. Os testes verificam o comportamento da regra; não medem eficácia contra ataques reais.

## Estrutura

- `triage.py`: CLI, validação e regra temporal.
- `test_triage.py`: testes de limites, dados inválidos, fusos, IPv6 e execução da CLI.
- `examples/auth.jsonl`: entrada sintética reproduzível.

## Próximos passos

Criar adaptadores para formatos reais, avaliar falsos positivos com conjuntos rotulados e reduzir uso de memória. Esses itens ainda não estão implementados.

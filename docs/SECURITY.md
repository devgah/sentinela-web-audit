# Política de segurança

## Escopo aceito

O Sentinela Web Audit é uma ferramenta passiva e local. Recebemos relatos sobre:

- falhas no tratamento de URLs, redirecionamentos ou Same Origin Policy;
- exposição indevida de valores de cookies ou dados do usuário em relatórios;
- execução de código, parsing inseguro ou paths inesperados;
- qualquer comportamento que envie dados a terceiros.

## Fora de escopo

- Pedidos para adicionar exploração, payloads, força bruta ou scanners ativos.
- Relatos sobre vulnerabilidades de sites de terceiros sem autorização do proprietário.
- Vulnerabilidades em dependências sem um caso de uso concreto neste projeto.

## Como relatar

Use o canal privado **Security** no repositório GitHub (`devgah/sentinela-web-audit`). Inclua versão, sistema operacional, passos mínimos de reprodução e impacto esperado. Não abra issues públicas com dados sensíveis.

## Versões suportadas

Apenas a versão `0.1.x` recebe correções nesta fase inicial do projeto.

## Compromisso de privacidade

Não há telemetria, login, coleta de dados pessoais, atualização automática ou upload de relatórios. A ferramenta só contata o alvo informado pelo usuário e grava arquivos no caminho escolhido por ele.

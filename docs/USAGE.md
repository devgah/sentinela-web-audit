# Guia de uso

## Antes de começar

Esta ferramenta é educacional e defensiva. Use-a **somente** em domínios que você possui ou para os quais possui autorização por escrito. O diálogo exibido na inicialização exige essa confirmação.

## Fluxo recomendado

1. Inicie com `sentinela-web-audit` (ou `python -m sentinela.ui.app`).
2. Confirme o aviso de uso responsável.
3. Informe a URL completa do alvo, por exemplo `https://exemplo.com`.
4. Clique em **Analisar** e acompanhe as etapas na barra de progresso.
5. Selecione um achado na tabela para ver risco, diagnóstico, evidência, remediação e referências.
6. Escolha Markdown, HTML ou PDF e clique em **Exportar relatório...**.

## O que é analisado

- Cabeçalhos de segurança: CSP, HSTS, X-Frame-Options, X-Content-Type-Options e Referrer-Policy.
- TLS do próprio alvo: protocolo, cipher, validade, emissor, SAN e correspondência de hostname.
- Atributos de cookies (`HttpOnly`, `Secure`, `SameSite`), sem ler ou gravar valores.
- CORS declarado em cabeçalhos, sem enviar requisições com `Origin` forjado.
- Arquivos públicos conhecidos: `robots.txt`, `sitemap.xml` e `security.txt`.
- Tecnologias reveladas por cabeçalhos e meta tags.

## O que **não** é feito

- Nenhuma exploração, payload, força bruta ou verificação agressiva de portas e caminhos.
- Nenhuma modificação do alvo.
- Nenhum fetch a hosts externos, CVE online, telemetria, analytics ou upload de relatório.
- Nenhuma leitura de proxies ou `.netrc` do ambiente.

## Formatos de relatório

| Formato | Extensão | Observações |
| --- | --- | --- |
| Markdown | `.md` | Texto puro, fácil de versionar localmente |
| HTML | `.html` | Arquivo único, CSS inline, sem JavaScript e com CSP offline |
| PDF | `.pdf` | Gerado em memória, sem fontes externas |

Todos incluem o aviso legal e a explicação de severidade.

## Privacidade

As únicas requisições de rede feitas pelo aplicativo são para o host informado por você. O relatório é gravado apenas no caminho escolhido no diálogo de arquivo. Não há preferências persistidas, contas, login ou identificadores de dispositivo.

## Solução de problemas

- **"Não foi possível acessar o alvo"**: confirme a URL, a conectividade e se o host responde dentro do timeout configurado.
- **"Falha de validação TLS"**: isso é um achado legítimo; o relatório registra a falha sem desativar a verificação do cliente HTTP.
- **Exportação não habilitada**: conclua uma análise antes de exportar.
- **Erro ao gravar**: escolha um diretório com permissão de escrita.

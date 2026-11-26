# Sentinela Web Audit

> Auditoria passiva de segurança web — 100% local, sem telemetria, sem login, sem coleta de dados.

Ferramenta desktop open source para analisar boas práticas de segurança em aplicações web a partir da máquina do usuário. Ela inspeciona a superfície pública (cabeçalhos HTTP, TLS, cookies, CORS, arquivos públicos e tecnologias expostas) e gera um relatório técnico com achados classificados por severidade e sugestões de correção baseadas em OWASP.

**Status:** Em construção — Dia 5/7 (relatórios Markdown/HTML/PDF).

## ⚠️ Disclaimer / Aviso legal

Esta ferramenta é fornecida **"como está"**, para **fins educacionais, treinamento e auditorias defensivas em domínios próprios ou expressamente autorizados**.

- Use **apenas** em alvos que você possui ou para os quais possui autorização por escrito.
- A ferramenta realiza **análise passiva**: não explora vulnerabilidades, não executa payloads de ataque, não faz força bruta, não realiza scanners agressivos e não modifica o alvo.
- Não há envio de dados para serviços externos: nenhuma telemetria, analytics, autenticação, API de terceiros ou upload de relatórios. A única comunicação de rede é a requisição ao próprio alvo informado pelo usuário.
- O uso indevido desta ferramenta é de responsabilidade exclusiva do usuário e pode violar leis locais. Os mantenedores não se responsabilizam por danos ou uso inadequado.
- Consulte a [Licença MIT](LICENSE) para os termos de uso do código.

## Princípios

- **Local-first:** execução e dados permanecem no computador do usuário.
- **Passivo por design:** inspeção de superfície, sem exploração ativa.
- **Didático:** cada achado explica risco, severidade e remediação.
- **Auditável:** código aberto, dependências conhecidas e build reproduzível.

## Stack proposta

| Camada | Tecnologia | Motivo |
| --- | --- | --- |
| Desktop | **PySide6 (Qt for Python)** | UI nativa multiplataforma, boa acessibilidade e empacotável |
| Lógica/redes | **Python 3.11+** + `requests` | HTTP com timeout, erros tratados e comportamento previsível |
| TLS | `cryptography` | Leitura de certificados, validade e emissor sem serviços externos |
| Parsing HTML | `beautifulsoup4` | Detecção passiva de meta tags e arquivos públicos |
| Relatórios | `Jinja2` + `reportlab` + Markdown | HTML offline com autoescape, Markdown e PDF gerados localmente |
| Empacotamento | **PyInstaller** | Executável local para Windows/Linux/macOS |
| Testes/qualidade | `pytest` + `ruff` | Testes automatizados e lint no Dia 7 |

> Alternativa considerada: **Tauri** (Rust + frontend web) gera binários menores, mas aumenta a complexidade dentro da janela de 7 dias. Para este escopo, Python + PySide6 entrega mais rápido com excelente suporte a TLS e relatórios.

**Nota de licença:** o código da aplicação é MIT. Dependências de terceiros mantêm suas próprias licenças (por exemplo, PySide6 é LGPLv3/comercial); os avisos correspondentes devem ser incluídos no pacote final.

## Motor HTTP e cabeçalhos (Dia 2)

- Normaliza a entrada para URLs absolutas `http`/`https`, rejeitando credenciais embutidas e caracteres de controle.
- Requisições com `timeout` de conexão/leitura, no máximo 5 redirecionamentos e verificação TLS sempre ativa.
- `trust_env = False`: não usa proxies nem `.netrc` do ambiente, evitando vazamentos involuntários.
- Apenas cabeçalhos são lidos (`stream=True`); URLs em relatórios são sanitizadas sem query, fragmento ou credenciais.
- Cabeçalhos avaliados: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options` e `Referrer-Policy`.

## TLS, cookies e CORS (Dia 3)

- **TLS:** handshake local para ler certificado apresentado, issuer, SAN, validade, protocolo e cipher. A leitura usa um contexto sem verificação apenas para obter certificados inválidos; uma segunda conexão com o contexto padrão do sistema valida cadeia e hostname. As requisições HTTP continuam com verificação ativa.
- **Cookies:** auditoria de `HttpOnly`, `Secure` e `SameSite` diretamente de `Set-Cookie`. Valores nunca são gravados no relatório — apenas o nome e os atributos observados.
- **CORS:** avaliação de `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, métodos/cabeçalhos e `Vary: Origin`, sem enviar requisições com `Origin` forjado.

## Descoberta passiva (Dia 4)

- Lê `robots.txt`, `sitemap.xml` (ou o sitemap declarado no robots, apenas na mesma origem) e `security.txt` nas localizações `/.well-known/` e raiz.
- Limita cada resposta textual a 512 KiB e ignora `DOCTYPE`/`ENTITY` em XML por precaução.
- Não segue links externos, não forja `Origin` e não testa caminhos adivinhados: apenas arquivos públicos conhecidos e a própria URL informada.
- Detecta tecnologias a partir de cabeçalhos como `Server`, `X-Powered-By`, `X-Generator` e de meta tags `generator`/`framework`, sem consultar bases de CVE externas.

## Relatórios (Dia 5)

- `ScanReport` reúne alvo, data de geração, achados, severidade máxima, contagem por nível e o mesmo aviso legal do README.
- Os achados são agrupados por severidade (Alto → Informativo) e trazem risco, status, diagnóstico, evidência sanitizada, remediação e referências OWASP.
- Markdown: texto puro, sem dependência de rede; conteúdo dinâmico é escapado para impedir HTML/Markdown injetado.
- HTML: template Jinja2 com autoescape, CSS inline, sem JavaScript e com CSP `default-src 'none'`.
- PDF: gerado em memória com ReportLab, sem fontes ou recursos externos; texto dinâmico é escapado e limitado ao conjunto latin-1.
- API local: `export_report(report, caminho)` infere o formato pela extensão (`.md`, `.html`, `.pdf`) ou aceita `ReportFormat`.
- Nenhum relatório é enviado, sincronizado ou hospedado: a gravação acontece apenas no caminho escolhido pelo usuário.

## Estrutura inicial

```text
.
├── LICENSE
├── README.md
├── pyproject.toml
├── .gitignore
├── src/
│   └── sentinela/
│       ├── __init__.py
│       ├── core/          # configuração, modelos e utilitários
│       ├── analyzers/     # headers, TLS, cookies, CORS e descoberta passiva
│       ├── reports/       # Markdown/HTML/PDF gerados localmente
│       └── ui/            # interface PySide6
├── tests/
├── docs/
├── assets/
└── packaging/
```

## Roadmap (7 dias)

- [x] **Dia 1** — Setup, stack, README com Disclaimer, MIT, `.gitignore` e estrutura de pastas
- [x] **Dia 2** — Motor HTTP e análise de cabeçalhos de segurança
- [x] **Dia 3** — TLS, cookies e CORS
- [x] **Dia 4** — Descoberta passiva (`robots.txt`, `sitemap.xml`, `security.txt`, tecnologias)
- [x] **Dia 5** — Gerador de relatórios Markdown/HTML/PDF com severidades e remediação
- [ ] **Dia 6** — Interface desktop com aviso de uso responsável, progresso e exportação
- [ ] **Dia 7** — Testes, revisão, build do executável e documentação final

## Como executar

A interface desktop ainda não está disponível; ela será documentada após o Dia 6. A exportação já pode ser usada pela API local:

```python
from sentinela.reports import ReportFormat, ScanReport, export_report

relatorio = ScanReport(target="https://exemplo.local")
caminho = export_report(relatorio, "relatorio.md", ReportFormat.MARKDOWN)
print(caminho)
```

## Como contribuir

Contribuições são bem-vindas depois que a base for estabilizada. Antes de abrir uma issue ou PR, confirme que a proposta continua estritamente defensiva, passiva e local.

## Licença

Distribuído sob a licença [MIT](LICENSE).

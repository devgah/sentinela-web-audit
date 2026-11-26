# Build e verificação

## Requisitos

- Python 3.11 ou superior.
- Dependências listadas em `pyproject.toml`.
- Para gerar o executável: PyInstaller 6.x.

## Ambiente de desenvolvimento

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
. .venv/bin/activate

python -m pip install -e ".[dev]"
```

Com `uv`, o equivalente é `uv venv .venv --python 3.12` e `uv pip install -e ".[dev]"`.

## Verificações locais

```bash
python -m pytest
python -m ruff check src tests
python -m compileall -q src
```

A suíte usa apenas respostas sintéticas, arquivos temporários e um backend gráfico `offscreen`. Nenhum teste depende de Internet.

## Gerando o executável

Na raiz do repositório:

```bash
# Windows (PowerShell)
.\packaging\build.ps1

# Linux/macOS
sh packaging/build.sh

# Comando equivalente, se preferir chamar diretamente
python -m PyInstaller --noconfirm --clean packaging/sentinela-web-audit.spec
```

O resultado fica em `dist/sentinela-web-audit/`. A especificação inclui o template Jinja2 do relatório HTML e os módulos necessários do PySide6. O diretório `dist/` está ignorado pelo Git.

## Observações

- PySide6 possui licença própria (LGPLv3/comercial); inclua os avisos correspondentes ao distribuir o binário.
- O código da aplicação é MIT, conforme `LICENSE`.
- O build não contata serviços externos além do gerenciador de pacotes usado para instalar as dependências.

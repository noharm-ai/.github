# Amazon Q Developer — Instruções de Review

## Supply Chain Security

Ao revisar Pull Requests, verifique obrigatoriamente os itens abaixo e sinalize
como erro (blocking) qualquer violação encontrada.

### 1. Versões de pacotes fixadas
- `requirements.txt` deve ter versões exatas (ex: `Flask==3.1.0`)
- Não aceitar ranges como `^`, `~`, `>=` ou sem versão
- Verificar se o arquivo possui hashes (`--hash=sha256:...`)

### 2. GitHub Actions referenciadas por SHA
- Todo `uses:` em arquivos `.github/workflows/*.yml` deve usar SHA completo
- Não aceitar referências por tag (ex: `@v4`) ou branch (ex: `@main`)
- Exemplo correto: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`

### 3. Uso de actions de provedores desconhecidos
- Sinalizar actions fora dos provedores aprovados:
  - `actions/*`, `aws-actions/*`, `docker/*`, `SocketDev/*`
- Qualquer action de conta individual ou organização desconhecida deve ser
  revisada com atenção

### 4. Socket.dev no workflow
- Workflows que instalam pacotes Python devem usar `sfw pip install`
  em vez de `pip install` direto
- A action `SocketDev/action` deve estar presente antes do step de instalação
```

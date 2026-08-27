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

## Vazamento de Segredos e Dados Sensiveis

A CI compartilhada ja roda gitleaks e o `pii-scan.py`, mas o scanner so pega
o que tem forma reconhecivel. No review, sinalize tambem:

### 5. Segredos em texto plano
- Senha, token, chave privada ou connection string com credencial embutida
- Senha fraca nao e detectada por entropia (ex: `"changeme123"`) — sinalize na
  leitura
- O valor correto vem de variavel de ambiente, SSM ou Secrets Manager

### 6. Detalhes de infraestrutura hardcoded
- IP publico, endpoint de RDS/Aurora/ElastiCache/OpenSearch/ELB, account ID da AWS
- IDs de rede (`vpc-`, `subnet-`, `sg-`) em codigo ou em `template.yaml`
- Devem ser `Parameter`/`Ref`/`${AWS::AccountId}`, nunca literal — o literal
  expoe a topologia da conta e prende o template a um ambiente so

### 7. PII brasileira
- CPF, CNPJ ou CNS validos em codigo, teste ou fixture
- Telefone que parece real (DDD valido + prefixo coerente), inclusive em
  docstring, README e fixture de teste
- Contexto de saude: dado de paciente e o ativo mais sensivel da NoHarm
- Fixture de teste deve usar numero **invalido** no digito verificador
  (ex: `111.222.333-44`), nunca um CPF que passe na validacao
- Para telefone, o equivalente e o placeholder: `(51) 99999-9999`,
  `(51) 3333-4444` — nunca um numero que poderia tocar em alguem

### 8. Supressoes
- `gitleaks:allow`, `noharm:allow-pii` (linha) e `noharm:allow-pii-file`
  (arquivo inteiro) silenciam o scanner
- Toda supressao nova precisa de justificativa no proprio comentario;
  supressao sem explicacao deve ser questionada no review


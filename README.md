# .github

Regras de CI centrais da NoHarm. Os repositorios da organizacao consomem este
workflow com um `.github/workflows/shared.yml` de tres linhas:

```yaml
jobs:
  call-shared:
    uses: noharm-ai/.github/.github/workflows/default.yml@main
```

Como o `ref` e `@main`, qualquer mudanca aqui vale para todos os repositorios no
PR seguinte.

## O que e verificado

| Job | Verificacao | Bloqueia? |
|---|---|---|
| `security-checks` | versoes fixas (`package.json`, `requirements.txt`, `pyproject.toml`), actions pinadas por SHA, `sfw` nos gerenciadores de pacote | sim |
| `secret-scan` | segredos reais (gitleaks, ruleset padrao) | **sim** |
| `secret-scan` | dados sensiveis de infra (IP publico, endpoint AWS, account ID, IDs de VPC) | nao (aviso) |
| `secret-scan` | PII brasileira: CPF, CNPJ, CNS, telefone | nao (aviso) |
| `iac-policy` | `cfn-lint` + cfn-guard IAM least-privilege (`iam-least-privilege.guard`) | sim |
| `iac-policy` | cfn-guard dados sensiveis em template (`no-sensitive-data.guard`) | nao (aviso) |

O escopo da varredura de segredos e a **arvore de trabalho**, nao o historico
do git. Um segredo que ja foi commitado e depois removido nao aparece aqui — a
correcao para esse caso e rotacionar a credencial, nao ajustar a CI.

O gitleaks detecta por formato de provedor (Stripe, GitHub, Slack…) e por
entropia com uma palavra-chave por perto (`key`, `token`, `secret`). Uma string
solta, sem contexto, pode passar: no gitleaks 8.30.1 um `AKIA...` sintetico so
e pego pela regra `generic-api-key`, e apenas quando ha uma atribuicao do tipo
`key = "..."` na linha. Ou seja, a varredura e uma rede de seguranca, nao uma
garantia — o review continua valendo.

Achados de infraestrutura aparecem como anotacao na aba **Files** do PR (o
`gitleaks` sozinho nao anota; a conversao e feita por
`security/gitleaks-annotate.py`). Os de PII tambem.

## Modo de aplicacao

O `default.yml` aceita dois inputs opcionais:

```yaml
jobs:
  call-shared:
    uses: noharm-ai/.github/.github/workflows/default.yml@main
    with:
      secret_scan_blocking: true      # padrao
      sensitive_data_blocking: false  # padrao — vire para true depois de limpar o repo
```

Segredos bloqueiam desde o primeiro dia (a varredura nos 14 repositorios
consumidores fechou em zero achado). Infra e PII entram em modo aviso porque
existem ocorrencias reais a limpar — principalmente `sg-`/`subnet-` e account
IDs hardcoded em `template.yaml`.

## Como silenciar um achado

Sao dois mecanismos diferentes; **nao sao intercambiaveis**:

| Camada | Supressao na linha |
|---|---|
| gitleaks (segredos e infra) | `gitleaks:allow` |
| `pii-scan.py` (CPF/CNPJ/CNS/telefone) | `noharm:allow-pii` |

Para um modulo cuja razao de existir e manipular PII — a suite que testa
normalizacao de telefone, por exemplo — suprimir linha a linha vira ruido. Nesse
caso use `noharm:allow-pii-file` em qualquer lugar do arquivo e ele inteiro sai
da varredura.

```python
BASTION_IP = "203.0.113.10"     # gitleaks:allow — IP publico documentado no runbook
CPF_FIXTURE = "111.222.333-44"  # noharm:allow-pii — fixture com digito verificador invalido
TELEFONE    = "(51) 99999-9999"  # noharm:allow-pii — placeholder, nao corresponde a ninguem
```

Para um valor que se repete em varios lugares, prefira
`security/allowlist.txt` (apenas CPF/CNPJ/CNS) em vez de espalhar comentarios.

Se o achado for legitimo, a correcao e tirar o dado do codigo: use Parameter,
SSM ou variavel de ambiente.

## Arquivos

- `.github/workflows/default.yml` — o workflow reutilizavel
- `security/gitleaks.toml` — regras de segredos (bloqueante)
- `security/gitleaks-infra.toml` — regras de infra (aviso)
- `security/pii-scan.py` — CPF/CNPJ/CNS por digito verificador; telefone por DDD + prefixo
- `security/gitleaks-annotate.py` — converte o JSON do gitleaks em anotacoes do PR
- `security/allowlist.txt` — valores liberados para o `pii-scan.py`
- `cfn-guard/iam-least-privilege.guard` — IAM least-privilege em templates SAM
- `cfn-guard/no-sensitive-data.guard` — senha em texto plano, CIDR publico, IDs de rede
- `amazon-q-developer-instructions.md` — instrucoes de review para o Amazon Q

## Rodando localmente antes do PR

```bash
gitleaks dir . --config /caminho/para/.github/security/gitleaks.toml --no-banner --redact
gitleaks dir . --config /caminho/para/.github/security/gitleaks-infra.toml --no-banner --redact
python /caminho/para/.github/security/pii-scan.py .
```

#!/usr/bin/env python3
"""Scanner de PII brasileira (CPF / CNPJ / CNS / telefone) para a CI compartilhada.

Por que um script e nao uma regra do gitleaks: regex nao calcula digito
verificador. Medido nos repositorios da organizacao, de 25 candidatos com
formato de CPF/CNPJ apenas 3 passam na validacao modulo 11 — fixtures de teste
como 123.456.789-00 e 11111111111 sao invalidos por construcao. Validar o
digito e o que torna esta regra utilizavel sem afogar os PRs em falso positivo.

Telefone nao tem digito verificador. O discriminante ali e outro: DDD que
existe de fato, prefixo coerente com celular (9) ou fixo (2-5), e descarte de
placeholder (99999-9999, 3333-4444, 90000-0000) — que e o que aparece nos
fixtures de teste da organizacao.

Somente biblioteca padrao: nao ha `pip install`, logo nao precisa de `sfw`
nem da action do SocketDev.

Escape hatches:
  - comentario `noharm:allow-pii` na mesma linha
  - valor listado em security/allowlist.txt

Uso:
    python pii-scan.py [CAMINHO] [--blocking] [--allowlist ARQUIVO]
"""

import argparse
import os
import re
import sys

EXCLUDED_DIRS = {
    ".git", ".noharm-shared", "node_modules", "site-packages", "__pycache__",
    "vendor", ".venv", "venv", "env", "dist", "build", "out", "coverage",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", ".nuxt",
}

EXCLUDED_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "uv.lock", "Pipfile.lock", "composer.lock",
}

EXCLUDED_SUFFIXES = (
    ".min.js", ".min.css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".pdf", ".woff", ".woff2", ".ttf", ".eot", ".zip", ".gz", ".tar", ".whl",
    ".so", ".dylib", ".map", ".lock",
)

ALLOW_MARKER = "noharm:allow-pii"
# Marcador de arquivo inteiro: para modulos cuja razao de existir e justamente
# manipular PII (ex: a suite que testa normalizacao de telefone), suprimir
# linha a linha e ruido. O marcador precisa aparecer no arquivo.
ALLOW_FILE_MARKER = "noharm:allow-pii-file"
MAX_BYTES = 2 * 1024 * 1024

CPF_FMT = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
CNPJ_FMT = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
# CNS nao tem pontuacao canonica: aparece como 15 digitos corridos ou em grupos
# de 3-4-4-4. Diferente de CPF/CNPJ nao havia como detecta-lo sem keyword, e
# `PACIENTE = "898001160580002"` — a forma de vazamento mais provavel num repo
# de saude — passava batido. O filtro aqui e o digito verificador: valid_cns
# rejeita a quase totalidade dos 15-digitos que nao sao CNS.
CNS_FMT = re.compile(r"(?<![0-9./-])\d{3}[\s.]?\d{4}[\s.]?\d{4}[\s.]?\d{4}(?![0-9./-])")
KEYED = re.compile(
    r"""(?i)\b(cpf|cnpj|cns|cart[aã]o[\s_]?sus|n[ur]_?cns)\b["']?\s*[:=]\s*["']?(\d{11,15})\b"""
)

# DDDs que existem no plano de numeracao brasileiro. Um par de digitos fora
# desta lista quase sempre e outra coisa (data, id, valor).
DDD_VALIDOS = frozenset({
    11, 12, 13, 14, 15, 16, 17, 18, 19,
    21, 22, 24, 27, 28,
    31, 32, 33, 34, 35, 37, 38,
    41, 42, 43, 44, 45, 46, 47, 48, 49,
    51, 53, 54, 55,
    61, 62, 63, 64, 65, 66, 67, 68, 69,
    71, 73, 74, 75, 77, 79,
    81, 82, 83, 84, 85, 86, 87, 88, 89,
    91, 92, 93, 94, 95, 96, 97, 98, 99,
})

# Telefone "forte": exige o prefixo de pais 55, ou parenteses no DDD, ou
# separador entre os dois blocos do assinante. Sem alguma dessas marcas um
# 11-digitos solto colidiria com CPF.
#
# A primeira alternativa aceita E.164 SEM o `+` e com todos os separadores
# opcionais, ou seja, `55` + 11 digitos corridos. Isso e deliberado: e a forma
# em que os numeros aparecem em campo `to` de integracao (ha ocorrencias reais
# em nifi-templates/NoHarm_Static_Flow.xml). O que segura o falso positivo nao
# e o formato e sim `valid_phone`, que exige DDD do plano de numeracao,
# assinante coerente (celular comeca em 9) e descarta placeholder — um id
# numerico qualquer comecando em 55 nao passa.
#
# Os grupos nomeados sairam: `candidates()` sempre usou `group(0)`.
PHONE_FMT = re.compile(
    r"""(?<![0-9])(?:
          \+?55[\s.-]?\(?[1-9][0-9]\)?[\s.-]?[0-9]{4,5}[\s.-]?[0-9]{4}
        | \([1-9][0-9]\)[\s.-]?[0-9]{4,5}[\s.-]?[0-9]{4}
        | [1-9][0-9][\s.-][0-9]{4,5}[\s.-][0-9]{4}
        )(?![0-9])""",
    re.VERBOSE,
)

# Telefone sem formatacao E SEM o prefixo 55 so e considerado quando ha uma
# chave por perto — ai o 10/11-digitos sozinho nao se distingue de um CPF ou de
# um id. Com o 55 na frente o PHONE_FMT acima ja resolve, sem precisar de chave.
PHONE_KEYED = re.compile(
    r"""(?i)\b(telefone|celular|whatsapp|whats|fone|tel|phone|contato|msisdn)\b"""
    r"""["']?\s*[:=]\s*["']?\+?(?:55)?\s?(\d{10,11})\b"""
)


def digits(value):
    return [int(c) for c in value if c.isdigit()]


def phone_key(bare):
    """`+5551987654321` e `51987654321` sao o mesmo numero.

    PHONE_FMT captura o `55` do pais e PHONE_KEYED nao; sem normalizar, a mesma
    linha rende dois achados (duas anotacoes no PR) para um unico telefone, e um
    numero na allowlist so e reconhecido na forma exata em que foi anotado.
    """
    if len(bare) in (12, 13) and bare.startswith("55"):
        return bare[2:]
    return bare


def valid_cpf(value):
    d = digits(value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        if sum(d[i] * (n + 1 - i) for i in range(n)) * 10 % 11 % 10 != d[n]:
            return False
    return True


def valid_cnpj(value):
    d = digits(value)
    if len(d) != 14 or len(set(d)) == 1:
        return False
    for n, weights in (
        (12, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]),
        (13, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]),
    ):
        rest = sum(d[i] * weights[i] for i in range(n)) % 11
        if (0 if rest < 2 else 11 - rest) != d[n]:
            return False
    return True


def valid_cns(value):
    """Cartao Nacional de Saude: definitivo (1/2) ou provisorio (7/8/9)."""
    d = digits(value)
    if len(d) != 15 or len(set(d)) == 1:
        return False
    if d[0] in (7, 8, 9):
        return sum(d[i] * (15 - i) for i in range(15)) % 11 == 0
    if d[0] not in (1, 2):
        return False
    pis = d[:11]
    total = sum(pis[i] * (15 - i) for i in range(11))
    dv = 11 - (total % 11)
    if dv == 11:
        dv = 0
    if dv == 10:
        total += 2
        dv = 11 - (total % 11)
        expected = pis + [0, 0, 1, dv]
    else:
        expected = pis + [0, 0, 0, dv]
    return expected == d


def _placeholder(seq):
    """Numero de assinante obviamente sintetico: 99999999, 33334444, 12345678."""
    if len(set(seq)) <= 2:
        return True
    crescente = all(seq[i + 1] - seq[i] == 1 for i in range(len(seq) - 1))
    decrescente = all(seq[i] - seq[i + 1] == 1 for i in range(len(seq) - 1))
    return crescente or decrescente


def valid_phone(value):
    """Telefone brasileiro plausivel: DDD real + prefixo coerente + nao placeholder."""
    d = digits(value)
    if len(d) == 13 and d[0] == 5 and d[1] == 5:
        d = d[2:]
    elif len(d) == 12 and d[0] == 5 and d[1] == 5:
        d = d[2:]
    if len(d) not in (10, 11):
        return False
    if d[0] * 10 + d[1] not in DDD_VALIDOS:
        return False
    assinante = d[2:]
    if len(assinante) == 9:
        if assinante[0] != 9:          # celular sempre comeca com 9
            return False
    elif assinante[0] not in (2, 3, 4, 5):  # fixo
        return False
    return not _placeholder(assinante)


VALIDATORS = {
    "CPF": valid_cpf,
    "CNPJ": valid_cnpj,
    "CNS": valid_cns,
    "TELEFONE": valid_phone,
}


def redact(value):
    """Mantem apenas os 4 ultimos caracteres — o log da Action e legivel por terceiros."""
    keep = 4
    if len(value) <= keep:
        return "*" * len(value)
    return "".join(
        c if (i >= len(value) - keep or not c.isdigit()) else "*"
        for i, c in enumerate(value)
    )


def load_allowlist(path):
    allowed = set()
    if not path or not os.path.isfile(path):
        return allowed
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                bare = "".join(c for c in line if c.isdigit())
                allowed.add(bare)
                # Guarda tambem a forma nacional, para que anotar o numero com
                # ou sem o 55 do pais tenha o mesmo efeito. Restrito a telefone:
                # sem o teste, uma entrada de 12 digitos qualquer acabaria
                # liberando de quebra o seu proprio sufixo de 10.
                if valid_phone(bare):
                    allowed.add(phone_key(bare))
    return allowed


def should_skip(name):
    return name in EXCLUDED_FILES or name.endswith(EXCLUDED_SUFFIXES)


def walk(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            if not should_skip(name):
                yield os.path.join(dirpath, name)


def candidates(line):
    """Devolve (tipo, valor_bruto) para cada trecho com forma de CPF/CNPJ/CNS."""
    for match in CPF_FMT.finditer(line):
        yield "CPF", match.group(0)
    for match in CNPJ_FMT.finditer(line):
        yield "CNPJ", match.group(0)
    for match in CNS_FMT.finditer(line):
        yield "CNS", match.group(0)
    for match in KEYED.finditer(line):
        raw = match.group(2)
        kind = {11: "CPF", 14: "CNPJ", 15: "CNS"}.get(len(raw))
        if kind:
            yield kind, raw
    for match in PHONE_FMT.finditer(line):
        yield "TELEFONE", match.group(0)
    for match in PHONE_KEYED.finditer(line):
        yield "TELEFONE", match.group(2)


def scan_file(path, allowed):
    findings = []
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return findings
        with open(path, "rb") as handle:
            blob = handle.read()
        if b"\0" in blob:
            return findings
        text = blob.decode("utf-8", errors="replace")
    except OSError:
        return findings

    if ALLOW_FILE_MARKER in text:
        return findings

    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        seen = set()
        for kind, raw in candidates(line):
            bare = "".join(c for c in raw if c.isdigit())
            key = phone_key(bare) if kind == "TELEFONE" else bare
            if bare in allowed or key in allowed or (kind, key) in seen:
                continue
            if not VALIDATORS[kind](bare):
                continue
            seen.add((kind, key))
            findings.append((path, number, kind, redact(raw)))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--blocking", action="store_true",
                        help="sai com codigo 1 quando houver achados")
    parser.add_argument("--allowlist", default=None,
                        help="arquivo de allowlist (padrao: allowlist.txt ao lado deste script)")
    args = parser.parse_args()

    allowlist_path = args.allowlist or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "allowlist.txt"
    )
    allowed = load_allowlist(allowlist_path)

    findings = []
    for path in walk(args.path):
        findings.extend(scan_file(path, allowed))

    level = "error" if args.blocking else "warning"
    for path, number, kind, masked in findings:
        rel = os.path.relpath(path, args.path) if os.path.isdir(args.path) else path
        # Nome de arquivo vem do PR e vai virar workflow command (::warning);
        # uma quebra de linha no nome forjaria anotacoes arbitrarias no log.
        rel = rel.replace("\r", " ").replace("\n", " ")
        if kind == "TELEFONE":
            dica = ("Use um placeholder (ex: (51) 99999-9999) em vez de um numero "
                    "que parece real.")
        else:
            dica = ("Remova o dado real ou use um valor de teste invalido no digito "
                    "verificador.")
        print(
            f"::{level} file={rel},line={number}::{kind} plausivel encontrado ({masked}). "
            f"{dica} Para suprimir: `{ALLOW_MARKER}` na linha, "
            f"`{ALLOW_FILE_MARKER}` no arquivo inteiro, "
            f"ou o valor em security/allowlist.txt"
        )

    if findings:
        kinds = ", ".join(sorted({f[2] for f in findings}))
        print(f"pii-scan: {len(findings)} achado(s) de PII ({kinds}).")
        return 1 if args.blocking else 0

    print("pii-scan: nenhum CPF/CNPJ/CNS/telefone plausivel encontrado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

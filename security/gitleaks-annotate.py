#!/usr/bin/env python3
"""Converte o relatorio JSON do gitleaks em anotacoes do GitHub Actions.

O gitleaks nao emite `::warning`/`::error`, entao um achado em modo aviso
ficaria so no log de um job verde — que ninguem abre. Isto coloca o achado na
aba Files do PR, que e o que torna o periodo de observacao util.

Uso: python gitleaks-annotate.py RELATORIO.json [--level warning|error]
"""

import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--level", default="warning", choices=("warning", "error"))
    parser.add_argument("--prefix", default="", help="prefixo a remover do caminho")
    args = parser.parse_args()

    if not os.path.isfile(args.report) or os.path.getsize(args.report) == 0:
        return 0

    try:
        with open(args.report, encoding="utf-8") as handle:
            findings = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"::warning::Nao foi possivel ler o relatorio do gitleaks: {exc}")
        return 0

    def clean(value):
        # O caminho vem do PR (e a descricao, do TOML de regras) e vai virar
        # workflow command (::warning); uma quebra de linha embutida forjaria
        # anotacoes arbitrarias no log.
        return str(value).replace("\r", " ").replace("\n", " ")

    for finding in findings or []:
        path = finding.get("File", "")
        if args.prefix and path.startswith(args.prefix):
            path = path[len(args.prefix):].lstrip("/")
        path = clean(path)
        rule = clean(finding.get("RuleID", "?"))
        desc = clean(finding.get("Description") or "dado sensivel encontrado")
        print(
            f"::{args.level} file={path},line={finding.get('StartLine', 1)}::"
            f"[{rule}] {desc}. Use Parameter/SSM/variavel de ambiente, "
            f"ou `gitleaks:allow` na linha se o valor for publico de proposito."
        )

    print(f"gitleaks-annotate: {len(findings or [])} achado(s) anotado(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
CASDE - Parameter Scoring Engine (Módulo 3)

Cruza parâmetros coletados de múltiplas fontes (JS AST, Wayback, GAU, user)
e aplica scoring semântico baseado em dicionário de risco, priorizando
parâmetros com maior probabilidade de vulnerabilidade:

  IDOR / ACL  : id, user_id, account, uid, file_id, doc_id, order_id...
  SSRF        : url, uri, dest, host, proxy, image_url, webhook, callback...
  Redirect    : redirect, next, return_to, rurl, dest, goto, u...
  LFI / Path  : file, path, dir, page, template, view, include, download...
  Auth bypass : debug, admin, test, dev, bypass, role, access, superuser...
  SQLi        : q, query, search, filter, keyword, sort, order...

Uso:
  python3 param_scorer.py <arquivo.json>
    arquivo.json: {"params": ["id", "url", "debug", ...], "sources": {...}}

Saída (stdout): JSON com score por parâmetro e ranking ordenado.

Design: scoring é determinístico e auditável (sem modelo opaco). Cada termo do
dicionário tem peso; o score final = soma dos pesos dos termos que casam
(prefixo/contém/exato), com bônus de comprimento curto (params de 2-6 chars
são mais comuns em apps vulneráveis a IDOR) e bônus por aparecer em várias
fontes (maior confiança de que é usado de verdade).
"""
import json
import re
import sys

# (regex, peso, categoria, motivo)
DICT = [
    (r"^(id|ids|pk|key|uid|gid|sid)$", 9, "idor", "identificador direto"),
    (r"(user|account|member|profile|employee|client|customer)_?(id|uuid|guid|no|num)?$", 8, "idor", "identificador de usuário"),
    (r"^(file|doc|order|invoice|ticket|product|item|message|photo|img|image|attach|upload|download|report|post|comment|review|team|org|project)_?(id|uuid)?$", 7, "idor", "identificador de recurso"),
    (r"^(url|uri|link|href|dest|destination|host|target|proxy|webhook|callback|redirect_?uri|return_?to|next|goto|rurl|u|out|path|image_?url|avatar_?url|src)$", 9, "ssrf/redirect", "destino de rede/redirect"),
    (r"(callback|return|redirect|next|continue|success_?url|failure_?url|ret)", 7, "redirect", "redirect pós-auth"),
    (r"^(file|path|dir|folder|page|view|template|include|require|load|read|open|doc|pdf|download|attachment|static|media|lang|locale|theme|style|module|script|plugin|data)$", 8, "lfi/path", "caminho/arquivo"),
    (r"(path|file|filename|document|page|template|view|include)", 6, "lfi/path", "manipulação de arquivo"),
    (r"^(debug|test|dev|stage|mock|fake|bypass|admin|root|super|sudo|impersonate|sudo_?user|sudo_?mode|role|access|grant|auth|verify|confirm|is_admin|is_?admin|internal)$", 8, "auth", "flag de debug/admin"),
    (r"(admin|debug|test|bypass|verify|confirm|internal|trusted|superuser)", 6, "auth", "flag de autenticação"),
    (r"^(q|query|search|keyword|filter|term|text|name|title|sort|order|page|limit|offset|type|status|category|tag|from|to|date|start|end)$", 5, "sqli/filter", "parâmetro de query"),
    (r"(callback|webhook|notify|hook|endpoint)", 6, "oob", "callback OOB"),
    (r"^(api_?key|token|secret|key|access_?token|auth|password|pass|pwd|email|phone|cpf|cnpj)$", 7, "sensitive", "dado sensível"),
]

# Fontes conhecidas (bônus de confiança)
SOURCE_BONUS = {"js": 1.0, "wayback": 0.6, "gau": 0.6, "manual": 0.8}


def score_param(param: str, sources: list) -> dict:
    p = param.lower()
    best = {"score": 0.0, "cat": "generic", "why": []}
    for regex, weight, cat, motivo in DICT:
        if re.search(regex, p):
            if weight > best["score"]:
                best["score"] = float(weight)
                best["cat"] = cat
                best["why"] = [motivo]
            elif weight == best["score"]:
                best["why"].append(motivo)
    s = best["score"]

    # Bônus: parâmetro curto (IDOR clássico: id, uid, f, u)
    if 1 <= len(p) <= 6:
        s += 1.5
    elif 7 <= len(p) <= 12:
        s += 0.5

    # Bônus: multi-fonte (usado de verdade, não só citado)
    uniq = set(sources)
    s += 0.8 * (len(uniq) - 1) if len(uniq) > 1 else 0.0

    # Bônus de fonte
    for src in sources:
        s += SOURCE_BONUS.get(src, 0.0) * 0.3

    return {"param": param, "score": round(s, 2), "category": best["cat"], "why": best["why"]}


def main():
    if len(sys.argv) < 2:
        print("uso: python3 param_scorer.py <arquivo.json>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)

    params = data.get("params", [])
    sources = data.get("sources", {})  # param -> [js, wayback, ...]

    results = [score_param(p, sources.get(p, [])) for p in params]
    results.sort(key=lambda r: r["score"], reverse=True)

    out = {
        "total": len(results),
        "ranking": results,
        "top": results[:10],
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

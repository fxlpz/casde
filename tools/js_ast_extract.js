#!/usr/bin/env node
/**
 * CASDE - JS AST Extractor (Módulo 2)
 *
 * Parser de AST real (esprima) para extrair de um arquivo JS:
 *   - chamadas fetch/axios/XHR com paths (estáticos E dinâmicos via template)
 *   - configs de rota (React Router / Vue Router / Next.js)
 *   - strings candidatas a segredo (entropia Shannon + padrão de nomenclatura)
 *   - concatenações de string que montam URLs
 *
 * Uso:  node js_ast_extract.js <arquivo.js>
 * Saída: JSON em stdout: { "endpoints": [...], "secrets": [...], "routes": [...] }
 *
 * Design: caminha o AST (Program -> Statements/Expressions) sem eval de código,
 * só leitura estática. Nada é executado: seguro para bundles desconhecidos.
 */
"use strict";

const fs = require("fs");
const esprima = require("esprima");

// ---------------------------------------------------------------------------
// Entropia de Shannon: detecta strings aleatórias (candidatas a secret).
// Alta entropia + padrão de nome = forte candidato.
// ---------------------------------------------------------------------------
function shannonEntropy(s) {
  if (s.length < 8) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = s.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Padrões de nomenclatura de segredos comuns em bundles.
const SECRET_KEY_PATTERNS = [
  /(api[_-]?key|apikey)/i,
  /(secret|token|access[_-]?token|auth[_-]?token|bearer)/i,
  /(private[_-]?key|pem|pkcs)/i,
  /(aws[_-]?secret|aws[_-]?access|s3[_-]?secret)/i,
  /(client[_-]?secret|client[_-]?id)/i,
  /(firebase|supabase|stripe[_-]?pk|stripe[_-]?sk|ghp_|sk_live|pk_live|AIza)/i,
  /(password|passwd|pwd|credential)/i,
  /(session|jwt|sso)/i,
];

// ---------------------------------------------------------------------------
// Caminhada do AST
// ---------------------------------------------------------------------------
class Extractor {
  constructor() {
    this.endpoints = new Set();
    this.routes = new Set();
    this.secrets = [];
  }

  // Resolve um nó de expressão para o valor literal mais provável (string).
  static literalValue(node) {
    if (!node) return null;
    if (node.type === "Literal" && typeof node.value === "string") {
      return node.value;
    }
    // Template literal sem interpolação: vira string pura.
    if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
      return node.quasis.map((q) => q.value.cooked).join("");
    }
    return null;
  }

  // Reconstrói parcialmente um template literal: {`/api/${id}`} -> "/api/${...}"
  static templatePattern(node) {
    if (!node || node.type !== "TemplateLiteral") return null;
    let out = "";
    for (let i = 0; i < node.quasis.length; i++) {
      out += node.quasis[i].value.cooked || "";
      if (i < node.expressions.length) out += "${...}";
    }
    return out;
  }

  // Reconstrói concatenações de string, ex.: API + "/users/" + id -> "…/users/$…"
  // Só concatena literais constantes; variáveis viram "$…" (não avaliamos código).
  static concatPattern(node) {
    if (!node) return null;
    if (node.type === "BinaryExpression" && node.operator === "+") {
      const l = Extractor.strValue(node.left);
      const r = Extractor.strValue(node.right);
      if (l === null && r === null) return null;
      return (l === null ? "$…" : l) + (r === null ? "$…" : r);
    }
    return null;
  }

  // Retorna string para literal/template, ou null para variável (marcada "$…").
  static strValue(node) {
    if (!node) return null;
    if (node.type === "Literal" && typeof node.value === "string") return node.value;
    if (node.type === "TemplateLiteral" && node.expressions.length === 0)
      return node.quasis.map((q) => q.value.cooked).join("");
    const concat = Extractor.concatPattern(node);
    if (concat !== null) return concat;
    // Identificador: deixa o nome como placeholder de variável.
    if (node.type === "Identifier") return "$" + node.name;
    return null;
  }

  // Detecta strings de URL dentro de argumentos de chamadas.
  extractCall(node) {
    const callee = node.callee;
    let name = "";
    if (callee.type === "Identifier") name = callee.name;
    else if (callee.type === "MemberExpression") {
      const obj = callee.object;
      if (obj.type === "Identifier") name = obj.name + "." + callee.property.name;
      else if (obj.type === "CallExpression") name = "call()";
    } else if (callee.type === "CallExpression") {
      name = "call()";
    }

    const isHttpCall =
      /^fetch$/.test(name) ||
      /^axios/.test(name) ||
      /\.axios$/.test(name) ||
      /\.(get|post|put|delete|patch|request)$/.test(name) ||
      /^XMLHttpRequest/.test(name) ||
      /\.open\(/.test(name) ||
      /\.fetch\(/.test(name) ||
      /sendBeacon/.test(name);

    if (!isHttpCall) return;

    // fetch(url, opts) | axios.get(url) | xhr.open(method, url)
    const args = node.arguments || [];
    let urlNode = null;
    if (name === "fetch" || name === "window.fetch" || name === "globalThis.fetch") {
      urlNode = args[0];
    } else if (name === "XMLHttpRequest" || /\.open\(/.test(name)) {
      urlNode = args[1];
    } else {
      urlNode = args[0];
    }

    const lit = Extractor.literalValue(urlNode);
    const tpl = Extractor.templatePattern(urlNode);
    const ident = urlNode && urlNode.type === "Identifier" ? urlNode.name : null;
    const concat = Extractor.concatPattern(urlNode);

    if (lit && /https?:\/\/|\/api|\//.test(lit)) this.endpoints.add(lit);
    if (tpl) this.endpoints.add(tpl);
    if (concat && /https?:\/\/|\/api|\//.test(concat)) this.endpoints.add(concat);
    if (ident) this.endpoints.add("$" + ident); // referência a variável (resolvida depois)

    // httpMethod(opts) com URL dentro de opts
    if (urlNode && urlNode.type === "ObjectExpression") {
      for (const prop of urlNode.properties) {
        if (prop.key && prop.key.name === "url") {
          const v = Extractor.literalValue(prop.value);
          if (v) this.endpoints.add(v);
        }
      }
    }
  }

  // Configs de rota: React Router <Route path="/x">, createBrowserRouter,
  // Vue Router routes: [{ path: "/x" }], Next.js pages.
  extractRoute(node) {
    // JSX <Route path="...">  (esprima não parseia JSX por padrão, mas
    // esprima.parse com jsx:true falha; tratamos via objeto de config).
    if (node.type === "Property" && node.key) {
      const keyName = node.key.name || node.key.value;
      if (keyName === "path" || keyName === "route") {
        const v = Extractor.literalValue(node.value);
        if (v && v.startsWith("/")) this.routes.add(v);
      }
    }
    // createBrowserRouter([...]) / Vue Router createRouter({routes:[...]})
    if (node.type === "CallExpression" && node.callee.type === "Identifier") {
      if (/createBrowserRouter|createRouter|createMemoryRouter/.test(node.callee.name)) {
        this.scanNestedPaths(node);
      }
    }
  }

  // Varre recursivamente arrays/objetos atrás de chaves path:"/..." e routes:[...]
  scanNestedPaths(node) {
    if (!node) return;
    if (node.type === "Property") {
      const keyName = node.key && (node.key.name || node.key.value);
      if (keyName === "path" || keyName === "route" || keyName === "to") {
        const v = Extractor.literalValue(node.value);
        if (v && v.startsWith("/")) this.routes.add(v);
      }
      this.scanNestedPaths(node.value);
    } else if (node.type === "ArrayExpression") {
      node.elements.forEach((el) => this.scanNestedPaths(el));
    } else if (node.type === "ObjectExpression") {
      node.properties.forEach((p) => this.scanNestedPaths(p));
    } else if (node.type === "CallExpression" || node.type === "NewExpression") {
      node.arguments.forEach((a) => this.scanNestedPaths(a));
    }
  }

  // Candidatos a secret: nome da propriedade bate padrão + valor com entropia alta.
  extractSecret(node) {
    if (node.type !== "Property") return;
    const keyName = node.key && (node.key.name || node.key.value);
    if (!keyName || typeof keyName !== "string") return;
    const val = Extractor.literalValue(node.value);
    if (!val || val.length < 10) return;

    const nameMatch = SECRET_KEY_PATTERNS.some((re) => re.test(keyName));
    const entropy = shannonEntropy(val);
    const looksRandom = entropy > 3.2;

    if (nameMatch && (looksRandom || /[A-Za-z0-9_-]{20,}/.test(val))) {
      this.secrets.push({
        key: keyName,
        value_preview: val.slice(0, 12) + "…", // preview apenas, não o valor
        value_length: val.length,
        entropy: +entropy.toFixed(2),
        source: "property",
      });
    }
    // Strings soltas com prefixo conhecido (ghp_, sk_live, AIza...)
    if (/^(ghp_|gho_|sk_live|sk_test|pk_live|rk_live|AIza|AKIA|ASIA|eyJ)/.test(val)) {
      this.secrets.push({
        key: "(literal)",
        value_preview: val.slice(0, 12) + "…",
        value_length: val.length,
        entropy: +entropy.toFixed(2),
        source: "literal",
      });
    }
  }

  walk(node) {
    if (!node || typeof node.type !== "string") return;
    switch (node.type) {
      case "CallExpression":
      case "NewExpression":
        this.extractCall(node);
        this.extractRoute(node);
        break;
      case "Property":
        this.extractSecret(node);
        this.extractRoute(node);
        break;
    }
    for (const key in node) {
      if (key === "parent") continue;
      const child = node[key];
      if (Array.isArray(child)) {
        for (const c of child) this.walk(c);
      } else if (child && typeof child.type === "string") {
        this.walk(child);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  const file = process.argv[2];
  if (!file) {
    console.error("uso: node js_ast_extract.js <arquivo.js>");
    process.exit(2);
  }
  let src;
  try {
    src = fs.readFileSync(file, "utf8");
  } catch (e) {
    console.error(`erro ao ler ${file}: ${e.message}`);
    process.exit(1);
  }

  let ast;
  try {
    ast = esprima.parse(src, { tolerant: true, loc: true });
  } catch (e) {
    // Bundle com sintaxe moderna não suportada (ex.: JSX, decorators).
    // esprima é tolerante a muitos erros; se falhar, reportamos parse_error.
    console.error(`parse_error: ${e.message}`);
    process.exit(3);
  }

  const ex = new Extractor();
  ex.walk(ast);

  const out = {
    file: file,
    endpoints: [...ex.endpoints],
    routes: [...ex.routes],
    secrets: ex.secrets,
    stats: {
      endpoints_found: ex.endpoints.size,
      routes_found: ex.routes.size,
      secrets_found: ex.secrets.length,
    },
  };
  console.log(JSON.stringify(out, null, 2));
}

main();

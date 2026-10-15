// compiler/lexer.js
// ĀML_CORE v1.1 — Lexer

export function tokenize(source) {
  const tokens = [];
  let i = 0;
  let line = 1;
  let column = 1;

  const keywords = new Set([
    "transmission",
    "engram",
    "coherence_gate",
    "mirror",
    "condition",
    "behavior",
    "render",
    "runtime",
    "attention",
    "memory",
    "purpose"
  ]);

  function addToken(type, value, startLine = line, startColumn = column) {
    tokens.push({ type, value, line: startLine, column: startColumn });
  }

  function advance() {
    const char = source[i++];
    if (char === "\n") {
      line++;
      column = 1;
    } else {
      column++;
    }
    return char;
  }

  function peek(offset = 0) {
    return source[i + offset];
  }

  while (i < source.length) {
    const char = peek();

    if (/\s/.test(char)) {
      advance();
      continue;
    }

    if (char === "/" && peek(1) === "/") {
      while (i < source.length && peek() !== "\n") advance();
      continue;
    }

    if (char === "/" && peek(1) === "*") {
      advance();
      advance();
      while (i < source.length) {
        if (peek() === "*" && peek(1) === "/") {
          advance();
          advance();
          break;
        }
        advance();
      }
      continue;
    }

    if (char === "{") {
      addToken("LEFT_BRACE", "{");
      advance();
      continue;
    }

    if (char === "}") {
      addToken("RIGHT_BRACE", "}");
      advance();
      continue;
    }

    if (char === ":") {
      addToken("COLON", ":");
      advance();
      continue;
    }

    if ([">", "<", "=", "!"].includes(char)) {
      const startLine = line;
      const startColumn = column;
      let value = advance();
      if (peek() === "=") value += advance();
      addToken("OPERATOR", value, startLine, startColumn);
      continue;
    }

    if (char === '"') {
      const startLine = line;
      const startColumn = column;
      let value = "";
      advance();
      while (i < source.length && peek() !== '"') {
        if (peek() !== "\\") {
          value += advance();
          continue;
        }
        advance();
        const escaped = advance();
        const escapes = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (escaped === "u") {
          let hex = "";
          for (let digit = 0; digit < 4; digit++) hex += advance() ?? "";
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw new Error(`Invalid unicode escape at line ${startLine}, column ${startColumn}`);
          }
          value += String.fromCharCode(parseInt(hex, 16));
        } else if (Object.hasOwn(escapes, escaped)) {
          value += escapes[escaped];
        } else {
          throw new Error(`Invalid string escape at line ${startLine}, column ${startColumn}`);
        }
      }
      if (peek() !== '"') {
        throw new Error(`Unterminated string at line ${startLine}, column ${startColumn}`);
      }
      advance();
      addToken("STRING", value, startLine, startColumn);
      continue;
    }

    if (/[0-9-]/.test(char)) {
      const startLine = line;
      const startColumn = column;
      const literal = source.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/)?.[0];
      if (!literal || !Number.isFinite(Number(literal))) {
        throw new Error(`Invalid number at line ${startLine}, column ${startColumn}`);
      }
      for (let digit = 0; digit < literal.length; digit++) advance();
      addToken("NUMBER", Number(literal), startLine, startColumn);
      continue;
    }

    if (/[A-Za-z_Āā]/.test(char)) {
      const startLine = line;
      const startColumn = column;
      let value = "";
      while (i < source.length && /[A-Za-z0-9_Āā]/.test(peek())) value += advance();
      addToken(keywords.has(value) ? "KEYWORD" : "IDENTIFIER", value, startLine, startColumn);
      continue;
    }

    throw new Error(`Unexpected character "${char}" at line ${line}, column ${column}`);
  }

  addToken("EOF", null);
  return tokens;
}

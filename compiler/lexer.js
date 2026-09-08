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
      while (i < source.length && peek() !== '"') value += advance();
      if (peek() !== '"') {
        throw new Error(`Unterminated string at line ${startLine}, column ${startColumn}`);
      }
      advance();
      addToken("STRING", value, startLine, startColumn);
      continue;
    }

    if (/[0-9]/.test(char)) {
      const startLine = line;
      const startColumn = column;
      let value = "";
      while (i < source.length && /[0-9.]/.test(peek())) value += advance();
      addToken("NUMBER", Number(value), startLine, startColumn);
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

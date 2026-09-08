// compiler/parser.js
// ĀML_CORE v1.1 — Parser
// Converts AML tokens into an Abstract Syntax Tree while preserving simple policy expressions.

export function parse(tokens) {
  let current = 0;

  function peek(offset = 0) {
    return tokens[current + offset];
  }

  function previous() {
    return tokens[current - 1];
  }

  function isAtEnd() {
    return peek().type === "EOF";
  }

  function advance() {
    if (!isAtEnd()) current++;
    return previous();
  }

  function check(type, value = null) {
    const token = peek();
    if (!token || token.type !== type) return false;
    if (value !== null && token.value !== value) return false;
    return true;
  }

  function match(type, value = null) {
    if (!check(type, value)) return false;
    advance();
    return true;
  }

  function consume(type, message, value = null) {
    if (check(type, value)) return advance();

    const token = peek();
    throw new Error(
      `${message} at line ${token?.line ?? "unknown"}, column ${token?.column ?? "unknown"}`
    );
  }

  function parseProgram() {
    const body = [];

    while (!isAtEnd()) {
      body.push(parseStatement());
    }

    return {
      type: "Program",
      body
    };
  }

  function parseStatement() {
    if (check("KEYWORD") || check("IDENTIFIER")) {
      return parseBlockOrProperty();
    }

    const token = peek();
    throw new Error(
      `Unexpected token "${token.value}" at line ${token.line}, column ${token.column}`
    );
  }

  function parseBlockOrProperty() {
    const nameToken = advance();

    if (match("COLON")) {
      return parseProperty(nameToken);
    }

    let identifier = null;

    if (check("IDENTIFIER") || check("STRING")) {
      identifier = advance().value;
    }

    consume("LEFT_BRACE", `Expected "{" after ${nameToken.value}`);

    const children = [];

    while (!check("RIGHT_BRACE") && !isAtEnd()) {
      children.push(parseStatement());
    }

    consume("RIGHT_BRACE", `Expected "}" to close ${nameToken.value}`);

    return {
      type: "Block",
      name: nameToken.value,
      identifier,
      children
    };
  }

  function parseAtomicValue(nameToken) {
    if (check("STRING") || check("NUMBER") || check("IDENTIFIER") || check("KEYWORD")) {
      return advance().value;
    }

    const token = peek();
    throw new Error(
      `Expected property value for "${nameToken.value}" at line ${token.line}, column ${token.column}`
    );
  }

  function parseProperty(nameToken) {
    const left = parseAtomicValue(nameToken);

    if (check("OPERATOR")) {
      const operator = advance().value;
      const right = parseAtomicValue(nameToken);
      return {
        type: "Property",
        name: nameToken.value,
        value: `${left} ${operator} ${right}`,
        expression: { left, operator, right }
      };
    }

    return {
      type: "Property",
      name: nameToken.value,
      value: left
    };
  }

  return parseProgram();
}

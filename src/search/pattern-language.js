// src/search/pattern-language.js
// Tokenizer, parser, compiler, and matcher for the TCP pattern search DSL.
//
// Grammar (simplified):
//   pattern      := disjunction
//   disjunction  := sequence ('|' sequence)*
//   sequence     := element ('->' element)*
//   element      := '!' atom quantifier? | atom quantifier?
//   atom         := event_name constraint? | '(' pattern ')' | '*' | '.' | '$' | '^'
//   quantifier   := '+' | '?' | '{' NUMBER (',' NUMBER?)? '}'
//   constraint   := '[' condition (',' condition)* ']'
//   condition    := IDENT operator value
//   operator     := '=' | '!=' | '<' | '>' | '<=' | '>='
//   value        := NUMBER unit? | STRING
//   unit         := 'us' | 'ms' | 's' | 'min'

// ─── Token types ─────────────────────────────────────────────────────────────

const TT = {
    IDENT:    'IDENT',
    NUMBER:   'NUMBER',
    STRING:   'STRING',
    ARROW:    'ARROW',    // ->
    PIPE:     'PIPE',     // |
    BANG:     'BANG',     // !
    PLUS:     'PLUS',     // +
    QMARK:    'QMARK',    // ?
    STAR:     'STAR',     // *
    DOT:      'DOT',      // .
    LPAREN:   'LPAREN',   // (
    RPAREN:   'RPAREN',   // )
    LBRACE:   'LBRACE',   // {
    RBRACE:   'RBRACE',   // }
    LBRACKET: 'LBRACKET', // [
    RBRACKET: 'RBRACKET', // ]
    COMMA:    'COMMA',    // ,
    EQ:       'EQ',       // =
    NEQ:      'NEQ',      // !=
    LT:       'LT',       // <
    GT:       'GT',       // >
    LTE:      'LTE',      // <=
    GTE:      'GTE',      // >=
    DOLLAR:   'DOLLAR',   // $
    CARET:    'CARET',    // ^
    EOF:      'EOF'
};

// ─── Tokenizer ────────────────────────────────────────────────────────────────

function tokenize(src) {
    const tokens = [];
    let i = 0;

    while (i < src.length) {
        // Skip whitespace
        if (/\s/.test(src[i])) { i++; continue; }

        // Arrow ->
        if (src[i] === '-' && src[i + 1] === '>') {
            tokens.push({ type: TT.ARROW, pos: i }); i += 2; continue;
        }
        // Unicode arrow →
        if (src[i] === '\u2192') {
            tokens.push({ type: TT.ARROW, pos: i }); i++; continue;
        }
        // !=
        if (src[i] === '!' && src[i + 1] === '=') {
            tokens.push({ type: TT.NEQ, pos: i }); i += 2; continue;
        }
        // <=
        if (src[i] === '<' && src[i + 1] === '=') {
            tokens.push({ type: TT.LTE, pos: i }); i += 2; continue;
        }
        // >=
        if (src[i] === '>' && src[i + 1] === '=') {
            tokens.push({ type: TT.GTE, pos: i }); i += 2; continue;
        }

        const single = {
            '|': TT.PIPE, '!': TT.BANG, '+': TT.PLUS, '?': TT.QMARK,
            '*': TT.STAR, '.': TT.DOT,  '(': TT.LPAREN, ')': TT.RPAREN,
            '{': TT.LBRACE, '}': TT.RBRACE, '[': TT.LBRACKET, ']': TT.RBRACKET,
            ',': TT.COMMA, '=': TT.EQ, '<': TT.LT, '>': TT.GT, '$': TT.DOLLAR,
            '^': TT.CARET
        };
        if (single[src[i]]) {
            tokens.push({ type: single[src[i]], pos: i }); i++; continue;
        }

        // Number
        if (/[0-9]/.test(src[i])) {
            let num = '';
            const pos = i;
            while (i < src.length && /[0-9.]/.test(src[i])) num += src[i++];
            tokens.push({ type: TT.NUMBER, value: parseFloat(num), pos }); continue;
        }

        // Identifier (event names, constraint keys, units, string values)
        if (/[a-zA-Z_]/.test(src[i])) {
            let id = '';
            const pos = i;
            while (i < src.length && /[a-zA-Z0-9_]/.test(src[i])) id += src[i++];
            tokens.push({ type: TT.IDENT, value: id, pos }); continue;
        }

        // Single-quoted string
        if (src[i] === "'") {
            let s = '';
            const pos = i++;
            while (i < src.length && src[i] !== "'") s += src[i++];
            i++; // closing quote
            tokens.push({ type: TT.STRING, value: s, pos }); continue;
        }

        throw new ParseError(`Unexpected character '${src[i]}'`, i);
    }

    tokens.push({ type: TT.EOF, pos: src.length });
    return tokens;
}

// ─── Parse error ─────────────────────────────────────────────────────────────

class ParseError extends Error {
    constructor(message, position) {
        super(message);
        this.position = position;
    }
}

// ─── Parser (recursive descent) ──────────────────────────────────────────────

function parse(tokens) {
    let pos = 0;

    function peek() { return tokens[pos]; }
    function consume(type) {
        const tok = tokens[pos];
        if (type && tok.type !== type) {
            throw new ParseError(`Expected ${type} but got ${tok.type}`, tok.pos);
        }
        pos++;
        return tok;
    }
    function check(type) { return tokens[pos].type === type; }
    function match(...types) {
        if (types.includes(tokens[pos].type)) { pos++; return true; }
        return false;
    }

    function parsePattern() {
        return parseDisjunction();
    }

    function parseDisjunction() {
        const left = parseSequence();
        if (!check(TT.PIPE)) return left;
        const alternatives = [left];
        while (check(TT.PIPE)) {
            pos++; // consume |
            alternatives.push(parseSequence());
        }
        return { type: 'Disjunction', alternatives };
    }

    function parseSequence() {
        const elements = [parseElement()];
        while (check(TT.ARROW)) {
            pos++; // consume ->
            elements.push(parseElement());
        }
        if (elements.length === 1) return elements[0];
        return { type: 'Sequence', elements };
    }

    function parseElement() {
        const negated = check(TT.BANG);
        if (negated) pos++;

        const atom = parseAtom();
        const quantifier = parseQuantifier();

        return { type: 'Element', negated, atom, quantifier };
    }

    function parseAtom() {
        if (check(TT.CARET)) {
            const tok = consume();
            return { type: 'StartAnchor', pos: tok.pos };
        }

        if (check(TT.DOLLAR)) {
            const tok = consume();
            return { type: 'EndAnchor', pos: tok.pos };
        }

        if (check(TT.STAR) || check(TT.DOT)) {
            const tok = consume();
            return { type: 'Wildcard', pos: tok.pos };
        }

        if (check(TT.LPAREN)) {
            pos++; // consume (
            const inner = parsePattern();
            consume(TT.RPAREN);
            return { type: 'Group', inner };
        }

        // Event name: one or more IDENT segments joined by '_'
        if (!check(TT.IDENT)) {
            const tok = peek();
            throw new ParseError(`Expected event name or wildcard, got ${tok.type}`, tok.pos);
        }

        let name = consume(TT.IDENT).value;
        // Allow multi-word identifiers joined by underscore (already lexed as one IDENT
        // since the tokenizer reads [a-zA-Z0-9_]+, so this is a single token)

        const constraints = check(TT.LBRACKET) ? parseConstraints() : null;
        return { type: 'Event', name, constraints };
    }

    function parseQuantifier() {
        if (check(TT.PLUS))  { pos++; return { min: 1, max: Infinity }; }
        if (check(TT.QMARK)) { pos++; return { min: 0, max: 1 }; }
        if (check(TT.LBRACE)) {
            pos++; // consume {
            const minTok = consume(TT.NUMBER);
            const min = minTok.value;
            let max = min;
            if (check(TT.COMMA)) {
                pos++; // consume ,
                if (check(TT.RBRACE)) {
                    max = Infinity;
                } else {
                    max = consume(TT.NUMBER).value;
                }
            }
            consume(TT.RBRACE);
            return { min, max };
        }
        return null; // no quantifier = exactly once (min:1, max:1)
    }

    function parseConstraints() {
        consume(TT.LBRACKET);
        const conditions = [parseCondition()];
        while (check(TT.COMMA)) {
            pos++;
            // Peek ahead to see if next token is an IDENT (start of a condition),
            // not a number (which would be the comma inside {n,m} — but we only
            // reach here inside [] so it's always a condition)
            if (check(TT.IDENT)) {
                conditions.push(parseCondition());
            }
        }
        consume(TT.RBRACKET);
        return conditions;
    }

    function parseCondition() {
        const key = consume(TT.IDENT).value;
        const op = parseOperator();
        const val = parseValue();
        return { key, op, val };
    }

    function parseOperator() {
        const opMap = {
            [TT.EQ]: '=', [TT.NEQ]: '!=', [TT.LT]: '<',
            [TT.GT]: '>', [TT.LTE]: '<=', [TT.GTE]: '>='
        };
        const tok = peek();
        if (!opMap[tok.type]) throw new ParseError(`Expected operator`, tok.pos);
        pos++;
        return opMap[tok.type];
    }

    function parseValue() {
        if (check(TT.STRING)) {
            return { kind: 'string', value: consume(TT.STRING).value };
        }
        if (check(TT.NUMBER)) {
            const num = consume(TT.NUMBER).value;
            // Optional unit
            const unitMap = { us: 1, ms: 1000, s: 1000000, min: 60000000 };
            if (check(TT.IDENT) && unitMap[peek().value] !== undefined) {
                const unit = consume(TT.IDENT).value;
                return { kind: 'number', value: num * unitMap[unit], unit };
            }
            return { kind: 'number', value: num };
        }
        if (check(TT.IDENT)) {
            // String-like identifier value (e.g., dir=out)
            return { kind: 'string', value: consume(TT.IDENT).value };
        }
        throw new ParseError('Expected value', peek().pos);
    }

    const ast = parsePattern();
    if (!check(TT.EOF)) {
        throw new ParseError(`Unexpected token ${peek().type}`, peek().pos);
    }
    return ast;
}

// ─── Compiler ─────────────────────────────────────────────────────────────────
//
// Each compiled matcher is a function:
//   (sequence, startIndex) => { matched: boolean, endIndex: number }
//
// matchPattern() calls the top-level matcher with startIndex=0 and checks
// that the whole sequence is consumed.

function compileNode(node) {
    switch (node.type) {
        case 'Disjunction': return compileDisjunction(node);
        case 'Sequence':    return compileSequence(node);
        case 'Element':     return compileElement(node);
        default:
            throw new Error(`Unknown AST node type: ${node.type}`);
    }
}

function compileDisjunction({ alternatives }) {
    const matchers = alternatives.map(compileNode);
    return (seq, start) => {
        for (const m of matchers) {
            const r = m(seq, start);
            if (r.matched) return r;
        }
        return { matched: false, endIndex: start };
    };
}

function compileSequence({ elements }) {
    const compiled = elements.map(el => ({
        matcher: compileElement(el),
        hasVariableQuantifier: !el.negated && el.quantifier &&
            (el.quantifier.max === Infinity || el.quantifier.max !== el.quantifier.min),
        min: el.quantifier ? el.quantifier.min : 1,
        atomMatcher: compileAtom(el.atom)
    }));

    // Recursive matcher with backtracking for variable-width quantifiers
    function matchFrom(seq, pos, elemIdx) {
        if (elemIdx >= compiled.length) return { matched: true, endIndex: pos };

        const { matcher, hasVariableQuantifier, min, atomMatcher } = compiled[elemIdx];

        if (!hasVariableQuantifier) {
            // Fixed-width or no quantifier: match and continue
            const r = matcher(seq, pos);
            if (!r.matched) return { matched: false, endIndex: pos };
            return matchFrom(seq, r.endIndex, elemIdx + 1);
        }

        // Variable-width quantifier: greedy with backtracking.
        // First consume as many as possible, then try the rest of the
        // sequence. If it fails, back off one match at a time down to min.
        const positions = [pos]; // positions[i] = position after consuming i matches
        let cur = pos;
        while (true) {
            if (cur >= seq.length) break;
            const r = atomMatcher(seq, cur);
            if (!r.matched) break;
            cur = r.endIndex;
            positions.push(cur);
        }

        // Try from most consumed down to min
        for (let count = positions.length - 1; count >= min; count--) {
            const rest = matchFrom(seq, positions[count], elemIdx + 1);
            if (rest.matched) return rest;
        }
        return { matched: false, endIndex: pos };
    }

    return (seq, start) => matchFrom(seq, start, 0);
}

function compileElement({ negated, atom, quantifier }) {
    const atomMatcher = compileAtom(atom);
    const q = quantifier || { min: 1, max: 1 };

    // StartAnchor (^) / EndAnchor ($) — non-consuming assertions.
    // Bypass the generic quantifier loop (which has a `cur >= seq.length` guard that
    // would prevent $ from ever being called at end-of-sequence, and quantifiers are
    // meaningless for zero-width assertions).
    if (atom.type === 'EndAnchor' || atom.type === 'StartAnchor') {
        return atomMatcher;
    }

    if (negated) {
        // Negation is a negative lookahead: succeeds if the next event does NOT match
        // the atom. Does NOT consume an event — it only checks what's ahead.
        // This models "SYN -> !SYN_ACK" as "SYN followed by end-of-sequence or a
        // non-SYN_ACK event." The element after !X in a sequence will attempt to
        // consume from the same position.
        //
        // Special case: at end of sequence, there is nothing to check — the negation
        // succeeds vacuously (the thing we're negating simply never arrived).
        return (seq, start) => {
            if (start >= seq.length) {
                // Nothing more in the sequence — the negated event is absent. Succeed.
                return { matched: true, endIndex: start };
            }
            const r = atomMatcher(seq, start);
            // If the atom matches, negation fails. If it doesn't match, negation succeeds.
            // Either way, do NOT advance position — lookahead only.
            return r.matched
                ? { matched: false, endIndex: start }
                : { matched: true, endIndex: start };
        };
    }

    // Non-negated with quantifier: greedy matching
    return (seq, start) => {
        let cur = start;
        let count = 0;

        // Consume up to max matches
        while (count < q.max) {
            if (cur >= seq.length) break;
            const r = atomMatcher(seq, cur);
            if (!r.matched) break;
            cur = r.endIndex;
            count++;
        }

        if (count < q.min) return { matched: false, endIndex: start };
        return { matched: true, endIndex: cur };
    };
}

function compileAtom(atom) {
    switch (atom.type) {
        case 'StartAnchor':
            // ^ — matches only at start of sequence; does NOT consume an event
            return (seq, start) => ({
                matched: start === 0,
                endIndex: start
            });

        case 'EndAnchor':
            // $ — matches only at end of sequence; does NOT consume an event
            return (seq, start) => ({
                matched: start >= seq.length,
                endIndex: start
            });

        case 'Wildcard':
            // Matches any single event
            return (seq, start) => {
                if (start >= seq.length) return { matched: false, endIndex: start };
                return { matched: true, endIndex: start + 1 };
            };

        case 'Group':
            return compileNode(atom.inner);

        case 'Event': {
            const name = atom.name;
            const conditions = atom.constraints || [];
            const condCheckers = conditions.map(compileCondition);

            return (seq, start) => {
                if (start >= seq.length) return { matched: false, endIndex: start };
                const event = seq[start];
                if (!matchesEventName(event, name)) return { matched: false, endIndex: start };
                for (const check of condCheckers) {
                    if (!check(event)) return { matched: false, endIndex: start };
                }
                return { matched: true, endIndex: start + 1 };
            };
        }

        default:
            throw new Error(`Unknown atom type: ${atom.type}`);
    }
}

/**
 * Check whether an event (Level 1, 2, or 3) matches the DSL event name.
 *
 * Level 1 events: { flagType, dir, deltaTime }
 * Level 2 events: { phase, packetCount, duration, hasRst }
 * Level 3 events: { outcome }
 */
function matchesEventName(event, name) {
    // Level 1
    if (event.flagType !== undefined) return event.flagType === name;
    // Level 2
    if (event.phase !== undefined) return event.phase === name;
    // Level 3 — sequence contains a single { outcome } element
    if (event.outcome !== undefined) return event.outcome === name;
    return false;
}

function compileCondition({ key, op, val }) {
    const expected = val.value;

    return (event) => {
        const actual = getEventAttribute(event, key);
        if (actual === undefined) return false;
        return compare(actual, op, expected);
    };
}

/**
 * Get a named attribute from any abstraction-level event.
 * Level 1: flagType, dir, dt (alias for deltaTime), deltaTime, flags
 * Level 2: phase, count (alias for packetCount), packetCount, dur (alias for duration), duration
 * Level 3: outcome, dur (alias for duration), packets, bytes
 */
function getEventAttribute(event, key) {
    // Level 1
    if (event.flagType !== undefined) {
        switch (key) {
            case 'dir':       return event.dir;
            case 'dt':
            case 'deltaTime': return event.deltaTime;
            case 'flagType':  return event.flagType;
        }
    }
    // Level 2
    if (event.phase !== undefined) {
        switch (key) {
            case 'count':
            case 'packetCount': return event.packetCount;
            case 'dur':
            case 'duration':    return event.duration;
            case 'hasRst':      return event.hasRst;
        }
    }
    // Level 3
    if (event.outcome !== undefined) {
        switch (key) {
            case 'outcome': return event.outcome;
            case 'dur':
            case 'duration': return event.duration;
            case 'packets':  return event.packets;
            case 'bytes':    return event.bytes;
        }
    }
    return undefined;
}

function compare(actual, op, expected) {
    switch (op) {
        case '=':  return actual == expected;   // loose equality to allow 'out' == 'out'
        case '!=': return actual != expected;
        case '<':  return actual < expected;
        case '>':  return actual > expected;
        case '<=': return actual <= expected;
        case '>=': return actual >= expected;
        default:   return false;
    }
}

// ─── Level 3 compiler (special case) ─────────────────────────────────────────
//
// Level 3: each flow is a single { outcome } event. The pattern is an
// OR-list of outcome names / disjunction. We compile to a predicate
// over a single-element sequence.

function compileLevel3(ast) {
    const matcher = compileNode(ast);
    // Level 3 sequences have exactly one element (the outcome event).
    return (outcomeEvent) => {
        const seq = [outcomeEvent];
        const r = matcher(seq, 0);
        return r.matched;
    };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Parse a pattern string into an AST.
 * @param {string} patternString
 * @returns {Object} AST root node
 * @throws {ParseError} on syntax error
 */
export function parsePattern(patternString) {
    const tokens = tokenize(patternString.trim());
    return parse(tokens);
}

/**
 * Compile an AST into a MatcherFunction.
 * @param {Object} ast - From parsePattern()
 * @param {number} level - 1, 2, or 3
 * @returns {Function} Compiled matcher
 */
export function compilePattern(ast, level) {
    if (level === 3) {
        return compileLevel3(ast);
    }
    return compileNode(ast);
}

/**
 * Match a compiled matcher against an abstracted event sequence.
 *
 * For Level 3: matcher is a predicate (outcomeEvent) => boolean.
 *   sequence should be [{ outcome }] (single element).
 *
 * For Level 1/2: matcher is (seq, startIndex) => { matched, endIndex }.
 *   The pattern must match a *contiguous subsequence* starting from some
 *   index in the sequence. This allows patterns to match flows that have
 *   leading events before the pattern starts.
 *
 * @param {Function} matcher - From compilePattern()
 * @param {Object[]} abstractedSequence - Events from flow-abstractor.js
 * @param {number} level - 1, 2, or 3
 * @returns {{ matched: boolean, matchedRegions: Array<{start: number, end: number}> }}
 */
export function matchPattern(matcher, abstractedSequence, level) {
    if (level === 3) {
        const outcomeEvent = abstractedSequence[0] || { outcome: 'UNKNOWN_INVALID' };
        const matched = matcher(outcomeEvent);
        return {
            matched,
            matchedRegions: matched ? [{ start: 0, end: 1 }] : []
        };
    }

    // Level 1/2: scan for the first matching contiguous sub-sequence.
    // Note: endIndex may equal start for patterns ending in negation (zero-advance).
    // We accept any matched result, but skip start=0 zero-advance to avoid trivially
    // matching an empty-pattern against an empty sequence (which would always succeed).
    const matchedRegions = [];
    for (let start = 0; start < abstractedSequence.length; start++) {
        const result = matcher(abstractedSequence, start);
        if (result.matched) {
            matchedRegions.push({ start, end: result.endIndex });
            break; // Report the first match
        }
    }
    // Edge case: if the sequence is empty and the pattern is a pure negation
    // (succeeds vacuously on empty), we should still report a match.
    if (matchedRegions.length === 0 && abstractedSequence.length === 0) {
        const result = matcher(abstractedSequence, 0);
        if (result.matched) {
            matchedRegions.push({ start: 0, end: 0 });
        }
    }

    return {
        matched: matchedRegions.length > 0,
        matchedRegions
    };
}

/**
 * Validate a pattern string. Returns error info on invalid syntax.
 * @param {string} patternString
 * @returns {{ valid: boolean, error?: string, position?: number }}
 */
export function validatePattern(patternString) {
    if (!patternString || !patternString.trim()) {
        return { valid: false, error: 'Pattern is empty' };
    }
    try {
        parsePattern(patternString);
        return { valid: true };
    } catch (e) {
        return {
            valid: false,
            error: e.message,
            position: e.position
        };
    }
}

/**
 * High-level convenience: parse, compile, and match in one call.
 * @param {string} patternString
 * @param {Object[]} abstractedSequence
 * @param {number} level - 1, 2, or 3
 * @returns {{ matched: boolean, matchedRegions: Array, error?: string }}
 */
export function matchPatternString(patternString, abstractedSequence, level) {
    try {
        const ast = parsePattern(patternString);
        const matcher = compilePattern(ast, level);
        return matchPattern(matcher, abstractedSequence, level);
    } catch (e) {
        return { matched: false, matchedRegions: [], error: e.message };
    }
}

// src/search/pattern-ast-to-blocks.js
// Converts a parsePattern() AST back into PatternBlock[].
// Used for loading presets into the visual pattern builder.

import { parsePattern } from './pattern-language.js';

// Counter for generating unique block IDs
let _blockIdCounter = 0;
function _nextId() {
    return `block_${++_blockIdCounter}`;
}

// DSL token → display name (reverse of blocks-to-dsl.js mapping)
const DSL_TO_DISPLAY = {
    'SYN_ACK':     'SYN+ACK',
    'PSH_ACK':     'PSH+ACK',
    'ACK_FIN_PSH': 'ACK+FIN+PSH',
    'FIN_ACK':     'FIN+ACK',
    'RST_ACK':     'RST+ACK',
};

/**
 * Map an AST quantifier object to the PatternBlock quantifier schema.
 * AST quantifier: { min: number, max: number } where max may be Infinity.
 * Returns null if the quantifier represents "exactly once" (the default).
 *
 * @param {Object|null} astQuantifier
 * @returns {Object|null}
 */
function _mapQuantifier(astQuantifier) {
    if (!astQuantifier) return null;

    const { min, max } = astQuantifier;

    // {min:1, max:Infinity} → plus
    if (min === 1 && max === Infinity) {
        return { type: 'plus', min: 1, max: null };
    }

    // {min:0, max:1} → optional
    if (min === 0 && max === 1) {
        return { type: 'optional', min: 0, max: 1 };
    }

    // {min:1, max:1} — the default "exactly once", no quantifier needed
    if (min === 1 && max === 1) {
        return null;
    }

    // {min:n, max:n} where n > 1 → exact
    if (min === max && max !== Infinity) {
        return { type: 'exact', min, max };
    }

    // {min:n, max:Infinity} → range with open upper bound
    if (max === Infinity) {
        return { type: 'range', min, max: null };
    }

    // {min:n, max:m} → range
    return { type: 'range', min, max };
}

/**
 * Format a constraint value from the AST back to a string.
 * AST value: { kind: 'string'|'number', value: ..., unit?: string }
 *
 * @param {Object} astVal
 * @returns {string}
 */
// Unit multipliers used by the parser (pattern-language.js:276)
const UNIT_FACTORS = { us: 1, ms: 1000, s: 1000000, min: 60000000 };

function _formatConstraintValue(astVal) {
    if (!astVal) return '';
    if (astVal.kind === 'string') return String(astVal.value);
    // Number with unit — the parser pre-multiplies value by unit factor,
    // so we must divide back to recover the original user-facing number.
    if (astVal.unit) {
        const rawValue = astVal.value / (UNIT_FACTORS[astVal.unit] ?? 1);
        return `${rawValue}${astVal.unit}`;
    }
    return String(astVal.value);
}

/**
 * Convert a pattern node (Disjunction/Sequence/Element) into an array of
 * alternative block-arrays.  Each alternative is a PatternBlock[].
 * Returns null if any sub-element is not representable.
 *
 * @param {Object} node - AST Disjunction, Sequence, or Element node
 * @returns {Object[][]|null} Array of PatternBlock[] alternatives, or null
 */
function _patternToAlternatives(node) {
    if (node.type === 'Disjunction') {
        const result = [];
        for (const alt of node.alternatives) {
            const blocks = _nodeToBlocks(alt);
            if (blocks === null) return null;
            result.push(blocks);
        }
        return result;
    }
    const blocks = _nodeToBlocks(node);
    return blocks ? [blocks] : null;
}

/**
 * Convert a Sequence or single Element to a flat PatternBlock[].
 * Returns null if any sub-element is not representable.
 *
 * @param {Object} node - AST Sequence or Element node
 * @returns {Object[]|null} PatternBlock[] or null
 */
function _nodeToBlocks(node) {
    if (node.type === 'Sequence') {
        const blocks = [];
        for (const el of node.elements) {
            const block = _elementToBlock(el);
            if (block === null) return null;
            blocks.push(block);
        }
        return blocks;
    }
    // Single Element
    const block = _elementToBlock(node);
    return block ? [block] : null;
}

/**
 * Convert a single AST Element node to a PatternBlock.
 * Returns null if the element cannot be represented.
 *
 * @param {Object} element - AST Element node
 * @returns {Object|null} PatternBlock or null
 */
function _elementToBlock(element) {
    const { negated, atom, quantifier } = element;

    let flagType;
    let constraints = [];

    switch (atom.type) {
        case 'Wildcard':
            flagType = 'WILDCARD';
            break;

        case 'EndAnchor':
            flagType = '$';
            break;

        case 'StartAnchor':
            flagType = '^';
            break;

        case 'Event': {
            // Map DSL name back to display name
            flagType = DSL_TO_DISPLAY[atom.name] ?? atom.name;
            // Map constraints
            if (atom.constraints) {
                constraints = atom.constraints.map(c => ({
                    key: c.key,
                    op: c.op,
                    val: _formatConstraintValue(c.val)
                }));
            }
            break;
        }

        case 'Group': {
            const alternatives = _patternToAlternatives(atom.inner);
            if (alternatives === null) return null;
            return {
                id: _nextId(),
                flagType: 'GROUP',
                negated: !!negated,
                quantifier: _mapQuantifier(quantifier),
                constraints: [],
                alternatives
            };
        }

        default:
            return null;
    }

    return {
        id: _nextId(),
        flagType,
        negated: !!negated,
        quantifier: _mapQuantifier(quantifier),
        constraints
    };
}

/**
 * Convert a parsed DSL string to a PatternBlock array.
 *
 * Returns null when the pattern is a Disjunction (uses '|'), because
 * disjunctions cannot be represented in the visual block builder.
 * Also returns null on parse errors.
 *
 * @param {string} dslString
 * @returns {Object[]|null} PatternBlock[] or null
 */
export function dslToBlocks(dslString) {
    if (!dslString || !dslString.trim()) return [];

    let ast;
    try {
        ast = parsePattern(dslString.trim());
    } catch (_e) {
        return null;
    }

    // Disjunctions are not visually representable
    if (ast.type === 'Disjunction') {
        return null;
    }

    // A single Element (no -> arrows)
    if (ast.type === 'Element') {
        const block = _elementToBlock(ast);
        return block ? [block] : null;
    }

    // A Sequence of elements joined by ->
    if (ast.type === 'Sequence') {
        const blocks = [];
        for (const element of ast.elements) {
            const block = _elementToBlock(element);
            if (block === null) {
                // Unrepresentable element (e.g. a Group) — abort
                return null;
            }
            blocks.push(block);
        }
        return blocks;
    }

    return null;
}

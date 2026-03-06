// src/search/blocks-to-dsl.js
// Pure utility: converts a PatternBlock[] into a DSL string.
//
// PatternBlock schema:
// {
//   id: string,
//   flagType: string,     // display name, e.g. 'SYN+ACK', 'WILDCARD'
//   negated: boolean,
//   quantifier: { type: 'exact'|'plus'|'optional'|'range', min: number, max: number|null } | null,
//   constraints: Array<{ key: string, op: string, val: string }>
// }

// Display name → DSL token
const DISPLAY_TO_DSL = {
    'SYN+ACK':     'SYN_ACK',
    'PSH+ACK':     'PSH_ACK',
    'ACK+FIN+PSH': 'ACK_FIN_PSH',
    'FIN+ACK':     'FIN_ACK',
    'RST+ACK':     'RST_ACK',
    'WILDCARD':    '.',
};

/**
 * Serialize a single PatternBlock to its DSL fragment.
 * @param {Object} block
 * @returns {string}
 */
function blockToDslFragment(block) {
    // Anchors — no quantifier or constraints
    if (block.flagType === '$' || block.flagType === '^') {
        return (block.negated ? '!' : '') + block.flagType;
    }

    // Group — parenthesized alternatives
    if (block.flagType === 'GROUP' && block.alternatives) {
        const altStrings = block.alternatives.map(
            altBlocks => altBlocks.map(blockToDslFragment).join(' -> ')
        );
        let fragment = block.negated ? '!' : '';
        fragment += `(${altStrings.join(' | ')})`;
        // Quantifier suffix
        if (block.quantifier) {
            const q = block.quantifier;
            switch (q.type) {
                case 'plus':    fragment += '+'; break;
                case 'optional': fragment += '?'; break;
                case 'exact':   fragment += `{${q.min}}`; break;
                case 'range':
                    fragment += (q.max === null || q.max === Infinity)
                        ? `{${q.min},}` : `{${q.min},${q.max}}`;
                    break;
            }
        }
        return fragment;
    }

    const dslName = DISPLAY_TO_DSL[block.flagType] ?? block.flagType;

    let fragment = block.negated ? '!' : '';
    fragment += dslName;

    // Constraints: [key=val,key2<val2]
    if (block.constraints && block.constraints.length > 0) {
        const parts = block.constraints.map(c => `${c.key}${c.op}${c.val}`);
        fragment += `[${parts.join(',')}]`;
    }

    // Quantifier
    if (block.quantifier) {
        const q = block.quantifier;
        switch (q.type) {
            case 'plus':
                fragment += '+';
                break;
            case 'optional':
                fragment += '?';
                break;
            case 'exact':
                fragment += `{${q.min}}`;
                break;
            case 'range':
                if (q.max === null || q.max === Infinity) {
                    fragment += `{${q.min},}`;
                } else {
                    fragment += `{${q.min},${q.max}}`;
                }
                break;
            default:
                break;
        }
    }

    return fragment;
}

/**
 * Convert a PatternBlock[] into a DSL string.
 * Blocks are joined with ' -> '.
 * Returns an empty string for an empty array.
 *
 * @param {Object[]} blocks - PatternBlock[]
 * @returns {string}
 */
export function blocksToDsl(blocks) {
    if (!blocks || blocks.length === 0) return '';
    return blocks.map(blockToDslFragment).join(' -> ');
}

// ─── Flow Arc Search Panel ───────────────────────────────────────────────────
//
// Floating search panel UI for flow-mode pattern search in attack-network.js.
// Follows the same visual conventions as #legendPanel.

import { FLOW_ARC_PRESETS, KILL_CHAIN_PHASES, CLOSE_TYPE_TOKENS } from '../search/flow-arc-presets.js';

let _panel = null;
let _callbacks = null;
let _collapsed = false;

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Initialize the flow arc search panel.
 * @param {Object} options
 * @param {Function} options.onSearch - (patternString, { withinMinutes }) => void
 * @param {Function} options.onFanSearch - (type, closeType, threshold, withinMinutes) => void
 * @param {Function} options.onClear - () => void
 */
export function initFlowArcSearchPanel(options) {
    _callbacks = options;
    _panel = document.getElementById('flowArcSearchPanel');
    if (!_panel) return;

    _panel.textContent = '';
    _panel.style.cssText = `
        position: fixed; top: 80px; left: 16px; width: 300px; max-height: 70vh;
        overflow-y: auto; z-index: 1000;
        background: rgba(255,255,255,0.97); border-radius: 8px;
        box-shadow: 0 2px 12px rgba(0,0,0,0.15); font-family: system-ui, sans-serif;
        font-size: 12px; color: #333;
    `;

    // ── Header (draggable, click to collapse) ──
    const header = _el('div', {
        style: 'padding: 8px 12px; background: #37474f; color: #fff; border-radius: 8px 8px 0 0; cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none;'
    });
    const headerTitle = _el('span', { text: 'Flow Pattern Search', style: 'font-weight:600;' });
    const collapseIcon = _el('span', { id: 'faspCollapseIcon', text: '\u25BC', style: 'font-size:11px;transition:transform 0.2s;' });
    header.appendChild(headerTitle);
    header.appendChild(collapseIcon);
    header.addEventListener('click', () => {
        _collapsed = !_collapsed;
        body.style.display = _collapsed ? 'none' : 'block';
        collapseIcon.style.transform = _collapsed ? 'rotate(-90deg)' : '';
    });
    _makeDraggable(_panel, header);
    _panel.appendChild(header);

    // ── Body ──
    const body = _el('div', { id: 'faspBody', style: 'padding: 10px 12px;' });
    _panel.appendChild(body);

    // ── Preset section ──
    const presetSection = _el('div', { style: 'margin-bottom: 10px;' });
    presetSection.appendChild(_el('div', { style: 'font-weight: 600; margin-bottom: 6px; color: #555;', text: 'Presets' }));

    for (const phase of KILL_CHAIN_PHASES) {
        const phasePresets = FLOW_ARC_PRESETS.filter(p => p.killChainPhase === phase.id && !p.fanType);
        if (phasePresets.length === 0) continue;

        presetSection.appendChild(_el('div', {
            style: `font-size: 10px; font-weight: 600; color: ${phase.color}; margin: 6px 0 3px; text-transform: uppercase; letter-spacing: 0.5px;`,
            text: phase.label
        }));

        const grid = _el('div', { style: 'display: flex; flex-wrap: wrap; gap: 4px;' });
        for (const preset of phasePresets) {
            const btn = _el('button', {
                style: `padding: 3px 8px; font-size: 10px; font-family: monospace; border: 1px solid #ccc; border-radius: 4px; background: #f5f5f5; cursor: pointer; white-space: nowrap; color: ${phase.color};`,
                text: preset.label,
                title: preset.pattern + '\n' + preset.description
            });
            btn.addEventListener('click', () => {
                patternInput.value = preset.pattern;
                if (withinInput && preset.withinMinutes) {
                    withinInput.value = preset.withinMinutes;
                }
                _doSearch();
            });
            grid.appendChild(btn);
        }
        presetSection.appendChild(grid);
    }
    body.appendChild(presetSection);

    // ── Pattern input ──
    const inputSection = _el('div', { style: 'margin-bottom: 10px;' });
    const patternInput = _el('textarea', {
        id: 'faspPatternInput',
        style: 'width: 100%; height: 40px; font-family: monospace; font-size: 11px; padding: 6px; border: 1px solid #ccc; border-radius: 4px; resize: vertical; box-sizing: border-box;',
        placeholder: 'e.g. GRACEFUL+ -> RST_HANDSHAKE+'
    });
    inputSection.appendChild(patternInput);

    // Options row
    const optRow = _el('div', { style: 'display: flex; align-items: center; gap: 8px; margin-top: 6px;' });
    optRow.appendChild(_el('span', { text: 'Within', style: 'font-size: 11px; color: #666;' }));
    const withinInput = _el('input', {
        id: 'faspWithinInput',
        type: 'number', min: '0', step: '1',
        style: 'width: 50px; font-size: 11px; padding: 3px; border: 1px solid #ccc; border-radius: 3px;',
        placeholder: '\u2014'
    });
    optRow.appendChild(withinInput);
    optRow.appendChild(_el('span', { text: 'min', style: 'font-size: 11px; color: #666;' }));

    const searchBtn = _el('button', {
        style: 'margin-left: auto; padding: 4px 14px; font-size: 11px; background: #1976d2; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;',
        text: 'Search'
    });
    searchBtn.addEventListener('click', _doSearch);
    optRow.appendChild(searchBtn);

    const clearBtn = _el('button', {
        style: 'padding: 4px 10px; font-size: 11px; background: #eee; color: #333; border: 1px solid #ccc; border-radius: 4px; cursor: pointer;',
        text: 'Clear'
    });
    clearBtn.addEventListener('click', () => {
        patternInput.value = '';
        withinInput.value = '';
        const resultsDiv = document.getElementById('faspResults');
        if (resultsDiv) resultsDiv.textContent = '';
        if (_callbacks?.onClear) _callbacks.onClear();
    });
    optRow.appendChild(clearBtn);

    inputSection.appendChild(optRow);
    body.appendChild(inputSection);

    // ── Fan pattern section ──
    const fanSection = _el('div', { style: 'margin-bottom: 10px; border-top: 1px solid #eee; padding-top: 8px;' });
    const fanHeader = _el('div', { style: 'font-weight: 600; margin-bottom: 6px; color: #555; cursor: pointer; user-select: none;', text: '\u25B8 Fan Patterns' });
    const fanBody = _el('div', { id: 'faspFanBody', style: 'display: none;' });
    fanHeader.addEventListener('click', () => {
        const visible = fanBody.style.display !== 'none';
        fanBody.style.display = visible ? 'none' : 'block';
        fanHeader.textContent = (visible ? '\u25B8' : '\u25BE') + ' Fan Patterns';
    });

    // Fan presets as quick buttons
    const fanPresets = FLOW_ARC_PRESETS.filter(p => p.fanType);
    const fanBtnRow = _el('div', { style: 'display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px;' });
    for (const fp of fanPresets) {
        const btn = _el('button', {
            style: 'padding: 3px 8px; font-size: 10px; border: 1px solid #ccc; border-radius: 4px; background: #f5f5f5; cursor: pointer;',
            text: fp.label,
            title: fp.description
        });
        btn.addEventListener('click', () => {
            if (_callbacks?.onFanSearch) {
                _callbacks.onFanSearch(fp.fanType, fp.closeType, fp.threshold, null);
            }
        });
        fanBtnRow.appendChild(btn);
    }
    fanBody.appendChild(fanBtnRow);

    // Custom fan inputs
    const fanRow = _el('div', { style: 'display: flex; align-items: center; gap: 6px; flex-wrap: wrap;' });
    const fanTypeSelect = _el('select', { style: 'font-size: 11px; padding: 2px;' });
    const fanInOpt = document.createElement('option');
    fanInOpt.value = 'fan_in'; fanInOpt.textContent = 'Fan-In (target)';
    const fanOutOpt = document.createElement('option');
    fanOutOpt.value = 'fan_out'; fanOutOpt.textContent = 'Fan-Out (source)';
    fanTypeSelect.appendChild(fanInOpt);
    fanTypeSelect.appendChild(fanOutOpt);
    fanRow.appendChild(fanTypeSelect);

    const fanCloseSelect = _el('select', { style: 'font-size: 11px; padding: 2px;' });
    for (const [ct, tok] of Object.entries(CLOSE_TYPE_TOKENS)) {
        const opt = document.createElement('option');
        opt.value = ct;
        opt.textContent = tok;
        fanCloseSelect.appendChild(opt);
    }
    fanRow.appendChild(fanCloseSelect);

    fanRow.appendChild(_el('span', { text: '>', style: 'font-size: 11px;' }));
    const fanThreshInput = _el('input', {
        type: 'number', min: '1', value: '5',
        style: 'width: 40px; font-size: 11px; padding: 2px; border: 1px solid #ccc; border-radius: 3px;'
    });
    fanRow.appendChild(fanThreshInput);

    const fanSearchBtn = _el('button', {
        style: 'padding: 3px 10px; font-size: 11px; background: #1976d2; color: #fff; border: none; border-radius: 4px; cursor: pointer;',
        text: 'Go'
    });
    fanSearchBtn.addEventListener('click', () => {
        if (_callbacks?.onFanSearch) {
            _callbacks.onFanSearch(
                fanTypeSelect.value, fanCloseSelect.value,
                parseInt(fanThreshInput.value) || 5, null
            );
        }
    });
    fanRow.appendChild(fanSearchBtn);
    fanBody.appendChild(fanRow);

    fanSection.appendChild(fanHeader);
    fanSection.appendChild(fanBody);
    body.appendChild(fanSection);

    // ── Results area ──
    body.appendChild(_el('div', { id: 'faspResults' }));

    // ── Progress ──
    body.appendChild(_el('div', { id: 'faspProgress', style: 'display: none; color: #1976d2; font-style: italic;' }));

    function _doSearch() {
        const pattern = patternInput.value.trim();
        if (!pattern) return;
        const within = parseInt(withinInput.value);
        if (_callbacks?.onSearch) {
            _callbacks.onSearch(pattern, { withinMinutes: isNaN(within) ? null : within });
        }
    }

    // Allow Enter to search (Shift+Enter for newline)
    patternInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            _doSearch();
        }
    });
}

/**
 * Show search results in the panel using safe DOM methods.
 * @param {FlowArcSearchResults} results
 * @param {Function} colorForAttack
 */
export function showFlowArcSearchResults(results, colorForAttack) {
    const div = document.getElementById('faspResults');
    if (!div) return;
    div.textContent = '';

    if (results.error) {
        const errDiv = _el('div', {
            style: 'color: #c62828; padding: 6px; background: #ffebee; border-radius: 4px; font-size: 11px;',
            text: results.error
        });
        div.appendChild(errDiv);
        return;
    }

    const wrapper = _el('div', { style: 'padding: 6px 0; border-top: 1px solid #eee;' });

    const countLine = _el('div', {
        style: 'font-weight: 600; color: #1976d2;',
        text: results.totalMatched + ' / ' + results.totalSearched + ' pairs matched'
    });
    wrapper.appendChild(countLine);

    const timeLine = _el('div', {
        style: 'font-size: 10px; color: #888;',
        text: 'in ' + results.searchTimeMs.toFixed(1) + 'ms'
    });
    wrapper.appendChild(timeLine);

    if (results.matchedPairKeys.size > 0) {
        const listDiv = _el('div', {
            style: 'margin-top: 6px; max-height: 120px; overflow-y: auto; font-family: monospace; font-size: 10px; line-height: 1.6;'
        });
        for (const pk of results.matchedPairKeys) {
            const [a, b] = pk.split('<->');
            const row = _el('div', { style: 'color: #333;', text: a + ' \u2194 ' + b });
            listDiv.appendChild(row);
        }
        wrapper.appendChild(listDiv);
    }

    div.appendChild(wrapper);
}

export function clearFlowArcSearchResults() {
    const div = document.getElementById('faspResults');
    if (div) div.textContent = '';
}

export function showFlowArcSearchProgress(label) {
    const div = document.getElementById('faspProgress');
    if (div) { div.textContent = label; div.style.display = 'block'; }
}

export function hideFlowArcSearchProgress() {
    const div = document.getElementById('faspProgress');
    if (div) div.style.display = 'none';
}

export function setFlowArcSearchPanelVisible(visible) {
    if (_panel) _panel.style.display = visible ? 'block' : 'none';
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function _el(tag, opts = {}) {
    const el = document.createElement(tag);
    if (opts.style) el.style.cssText = opts.style;
    if (opts.text) el.textContent = opts.text;
    if (opts.id) el.id = opts.id;
    if (opts.placeholder) el.placeholder = opts.placeholder;
    if (opts.type) el.type = opts.type;
    if (opts.min) el.min = opts.min;
    if (opts.max) el.max = opts.max;
    if (opts.step) el.step = opts.step;
    if (opts.value) el.value = opts.value;
    if (opts.title) el.title = opts.title;
    return el;
}

function _makeDraggable(panel, handle) {
    let startX, startY, startLeft, startTop;
    handle.addEventListener('mousedown', (e) => {
        if (e.target.tagName === 'BUTTON') return;
        e.preventDefault();
        startX = e.clientX;
        startY = e.clientY;
        const rect = panel.getBoundingClientRect();
        startLeft = rect.left;
        startTop = rect.top;

        function onMove(ev) {
            panel.style.left = (startLeft + ev.clientX - startX) + 'px';
            panel.style.top = (startTop + ev.clientY - startY) + 'px';
            panel.style.right = 'auto';
            panel.style.bottom = 'auto';
        }
        function onUp() {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
    });
}

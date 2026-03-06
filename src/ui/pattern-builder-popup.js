// src/ui/pattern-builder-popup.js
// Floating visual pattern builder popup for TCP flow pattern search.
// Replaces the old text-input-based pattern search panel.

import { blocksToDsl } from '../search/blocks-to-dsl.js';
import { dslToBlocks } from '../search/pattern-ast-to-blocks.js';
import { validatePattern } from '../search/pattern-language.js';
import { getPresetsForLevel } from '../search/pattern-presets.js';

// ─── Constants ────────────────────────────────────────────────────────────────

// Flag colors — seeded from DEFAULT_FLAG_COLORS, then overridden by flag_colors.json
// at runtime so the palette matches the visualization legend exactly.
const FLAG_COLORS = {
    'SYN':       '#757575',
    'SYN+ACK':   '#f39c12',
    'ACK':       '#27ae60',
    'PSH':       '#157256',
    'PSH+ACK':   '#3498db',
    'FIN':       '#8e44ad',
    'FIN+ACK':   '#9b59b6',
    'RST':       '#34495e',
    'RST+ACK':   '#c0392b',
    'ACK+FIN+PSH': '#e67e22',
    'OTHER':     '#2b2b2b',
    'WILDCARD':  '#6c757d',
    '$':         '#868e96',
    '^':         '#868e96',
    // Level 2 phases
    'HANDSHAKE': '#1a73e8',
    'DATA':      '#0f9d58',
    'FIN_CLOSE': '#7b1fa2',
    'RST_CLOSE': '#b71c1c',
    // Level 3 outcomes
    'COMPLETE_GRACEFUL': '#0f9d58',
    'COMPLETE_ABORTED':  '#c0392b',
    'ONGOING':           '#6c757d',
    'RST_HANDSHAKE':     '#b71c1c',
    'NO_SYNACK':         '#e65100',
    'NO_ACK':            '#f57f17',
    'INVALID_ACK':       '#880e4f',
    'INVALID_SYNACK':    '#4a148c',
    'UNKNOWN_INVALID':   '#212121',
};

// Load runtime flag colors from flag_colors.json and re-render palette.
// The file uses '+' notation (SYN+ACK) which matches our FLAG_COLORS keys.
function _loadFlagColors() {
    fetch('flag_colors.json')
        .then(r => r.json())
        .then(colors => {
            Object.assign(FLAG_COLORS, colors);
            _renderPalette(); // re-render palette with correct colors
        })
        .catch(() => { /* keep defaults on network error */ });
}

// Palette definitions per level
const LEVEL_PALETTE = {
    1: [
        'SYN', 'SYN+ACK', 'ACK', 'PSH+ACK', 'ACK+FIN+PSH', 'FIN+ACK', 'RST', 'RST+ACK'
    ],
    2: [
        'HANDSHAKE', 'DATA', 'FIN_CLOSE', 'RST_CLOSE'
    ],
    3: [
        'COMPLETE_GRACEFUL', 'COMPLETE_ABORTED', 'ONGOING',
        'RST_HANDSHAKE', 'NO_SYNACK', 'NO_ACK',
        'INVALID_ACK', 'INVALID_SYNACK', 'UNKNOWN_INVALID'
    ]
};

// Display label for special blocks in palette / sequence
const PALETTE_DISPLAY_LABEL = { 'WILDCARD': '·', '$': '$', '^': '^' };

// ─── Module state ─────────────────────────────────────────────────────────────

let _blocks = [];
let _fallbackDsl = null;     // Set when a disjunction preset is loaded
let _callbacks = {};
let _currentLevel = 1;
let _selectedBlockId = null; // ID of the currently-open constraint popover's block

// DOM refs populated during init
let _popupEl = null;
let _progressEl = null;
let _progressBarEl = null;
let _progressLabelEl = null;
let _resultsEl = null;
let _searchBtn = null;
let _cancelBtn = null;
let _clearBtn = null;
let _sequenceEl = null;
let _dslPreviewEl = null;
let _paletteEl = null;
let _presetSelect = null;
let _popoverEl = null;
let _filterActive = false;
let _levelRadios = {};
let _scopeRadios = {};
let _timeRangeRadios = {};

// Drag state for popup repositioning
let _dragState = null;
// Stored reference for document-level popover-close listener (cleanup on re-init)
let _docMousedownHandler = null;
// Group creator state: { alternatives: PatternBlock[][], anchorEl } or null
let _groupCreatorEl = null;

// Counter for unique block IDs
let _idCounter = 0;
function _nextId() { return `pb_${++_idCounter}`; }

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialize the popup. Must be called once after the DOM is ready.
 * Populates #patternBuilderPopup and wires the #openPatternBuilder button.
 *
 * @param {Object} options
 * @param {Function} options.onSearch           - async (pattern, level, scope) => void
 * @param {Function} options.onCancel           - () => void
 * @param {Function} options.onClear            - () => void
 * @param {Function} options.onFilterToggle     - (active: boolean) => void
 * @param {Function} options.onSelectMatchedIPs - (ips: string[]) => void
 */
export function initPatternBuilderPopup(options) {
    _callbacks = options || {};

    _popupEl = document.getElementById('patternBuilderPopup');
    if (!_popupEl) return;

    _popupEl.innerHTML = '';
    _buildPopupDOM();
    _wirePopupEvents();

    // Wire the trigger button in the control panel
    const openBtn = document.getElementById('openPatternBuilder');
    if (openBtn) {
        openBtn.addEventListener('click', showPatternBuilderPopup);
    }

    // Override hardcoded defaults with runtime flag_colors.json
    _loadFlagColors();
}

export function showPatternBuilderPopup() {
    if (!_popupEl) return;
    _popupEl.classList.remove('pb-hidden');
}

export function hidePatternBuilderPopup() {
    if (!_popupEl) return;
    _popupEl.classList.add('pb-hidden');
}

/**
 * Update the progress bar.
 * @param {number} pct   - 0.0 to 1.0
 * @param {string} label - Status text
 */
export function showSearchProgress(pct, label) {
    if (!_progressEl) return;
    _progressEl.style.display = 'block';
    const clamped = Math.round(Math.max(0, Math.min(1, pct)) * 100);
    _progressBarEl.style.width = `${clamped}%`;
    if (label && _progressLabelEl) _progressLabelEl.textContent = label;
}

export function hideSearchProgress() {
    if (_progressEl) _progressEl.style.display = 'none';
}

/**
 * Render search results in the popup.
 * @param {Object} results        - SearchResults object
 * @param {Function} onViewFlows  - Called with matched real flows
 * @param {Function} onSelectMatchedIPs - Called with matched IPs
 */
export function showSearchResults(results, onViewFlows, onSelectMatchedIPs) {
    if (!_resultsEl) return;

    if (results.error) {
        _resultsEl.innerHTML = `<div class="pb-error">${_esc(results.error)}</div>`;
        _resultsEl.style.display = 'block';
        _updateStatusIndicator(null);
        return;
    }

    const summary = results.getSummary();
    const realFlows = results.getRealFlows();

    let html = `<div class="pb-summary">${_esc(summary)}</div>`;

    if (results.totalMatches > 0) {
        html += `<div class="pb-result-buttons">`;
        if (realFlows.length > 0 && typeof onViewFlows === 'function') {
            html += `<button id="pbViewFlowsBtn" class="pb-btn pb-btn-primary">View Flows</button>`;
        }
        html += `<button id="pbSelectIPsBtn" class="pb-btn">Select IPs</button>`;
        html += `</div>`;
    }

    const checked = _filterActive ? ' checked' : '';
    html += `<label class="pb-filter-row">
        <input type="checkbox" id="pbFilterToggleInResults"${checked}> Highlight matches only
    </label>`;

    _resultsEl.innerHTML = html;
    _resultsEl.style.display = 'block';

    const viewBtn = document.getElementById('pbViewFlowsBtn');
    if (viewBtn && typeof onViewFlows === 'function') {
        viewBtn.addEventListener('click', () => onViewFlows(realFlows));
    }

    const selectBtn = document.getElementById('pbSelectIPsBtn');
    if (selectBtn) {
        selectBtn.addEventListener('click', () => {
            const ips = results.getMatchedIPs();
            if (typeof onSelectMatchedIPs === 'function') onSelectMatchedIPs(ips);
            else if (typeof _callbacks.onSelectMatchedIPs === 'function') _callbacks.onSelectMatchedIPs(ips);
        });
    }

    const filterInResults = document.getElementById('pbFilterToggleInResults');
    if (filterInResults) {
        filterInResults.addEventListener('change', () => {
            _filterActive = filterInResults.checked;
            if (typeof _callbacks.onFilterToggle === 'function') {
                _callbacks.onFilterToggle(_filterActive);
            }
        });
    }

    // Update the status indicator next to the open button
    _updateStatusIndicator(results.totalMatches);
}

export function clearSearchResults() {
    if (_resultsEl) {
        _resultsEl.innerHTML = '';
        _resultsEl.style.display = 'none';
    }
    hideSearchProgress();
    _updateStatusIndicator(null);
}

// ─── DOM construction ─────────────────────────────────────────────────────────

function _buildPopupDOM() {
    // Titlebar
    const titlebar = _el('div', 'pb-titlebar');
    const title = _el('span', 'pb-title');
    title.textContent = 'Pattern Search';
    const closeBtn = _el('button', 'pb-close');
    closeBtn.textContent = '✕';
    closeBtn.title = 'Close';
    closeBtn.setAttribute('aria-label', 'Close pattern builder');
    titlebar.appendChild(title);
    titlebar.appendChild(closeBtn);
    _popupEl.appendChild(titlebar);

    // Body
    const body = _el('div', 'pb-body');
    _popupEl.appendChild(body);

    // Section: Level + Scope
    const levelSection = _el('div', 'pb-section');
    levelSection.innerHTML = `
<div class="pb-row">
  <span class="pb-row-label">Level:</span>
  <label class="pb-radio-label"><input type="radio" name="pbLevel" value="1" checked> Packet</label>
  <label class="pb-radio-label pb-disabled"><input type="radio" name="pbLevel" value="2" disabled> Phase</label>
  <label class="pb-radio-label pb-disabled"><input type="radio" name="pbLevel" value="3" disabled> Outcome</label>
</div>
<div class="pb-row">
  <span class="pb-row-label">Scope:</span>
  <label class="pb-radio-label"><input type="radio" name="pbScope" value="selected" checked> Selected IPs</label>
  <label class="pb-radio-label"><input type="radio" name="pbScope" value="all"> All IPs</label>
</div>
<div class="pb-row">
  <span class="pb-row-label">Time:</span>
  <label class="pb-radio-label"><input type="radio" name="pbTimeRange" value="view" checked> Current View</label>
  <label class="pb-radio-label"><input type="radio" name="pbTimeRange" value="all"> All Time</label>
</div>`;
    body.appendChild(levelSection);

    // Section: Preset
    const presetSection = _el('div', 'pb-section');
    presetSection.innerHTML = `
<div class="pb-row">
  <span class="pb-row-label">Preset:</span>
  <select class="pb-select" id="pbPresetSelect">
    <option value="">-- Select preset --</option>
  </select>
</div>`;
    body.appendChild(presetSection);

    // Section: Palette (flags + symbols)
    const paletteSection = _el('div', 'pb-section pb-palette-section');
    const paletteSectionLabel = _el('div', 'pb-section-label');
    paletteSectionLabel.textContent = 'Add Flag';
    paletteSection.appendChild(paletteSectionLabel);
    _paletteEl = _el('div', 'pb-palette');
    paletteSection.appendChild(_paletteEl);

    // Symbols row: ^, $, wildcard, group creator
    const symbolsLabel = _el('div', 'pb-section-label');
    symbolsLabel.textContent = 'Symbols';
    symbolsLabel.style.marginTop = '6px';
    paletteSection.appendChild(symbolsLabel);
    const symbolsRow = _el('div', 'pb-symbols');
    symbolsRow.id = 'pbSymbolsRow';
    paletteSection.appendChild(symbolsRow);

    body.appendChild(paletteSection);

    // Group creator dialog (hidden by default, absolutely positioned)
    _groupCreatorEl = _el('div', 'pb-group-creator');
    _groupCreatorEl.id = 'pbGroupCreator';
    _groupCreatorEl.style.display = 'none';
    _popupEl.appendChild(_groupCreatorEl);

    // Section: Sequence
    const seqSection = _el('div', 'pb-section pb-sequence-section');
    const seqHeader = _el('div', 'pb-sequence-header');
    const seqLabel = _el('span', 'pb-section-label');
    seqLabel.textContent = 'Pattern:';
    const clearPatternBtn = _el('button', 'pb-clear-pattern-btn');
    clearPatternBtn.textContent = 'Clear Pattern';
    clearPatternBtn.id = 'pbClearPattern';
    seqHeader.appendChild(seqLabel);
    seqHeader.appendChild(clearPatternBtn);
    seqSection.appendChild(seqHeader);

    _sequenceEl = _el('div', 'pb-sequence');
    seqSection.appendChild(_sequenceEl);

    _dslPreviewEl = _el('div', 'pb-dsl-preview');
    seqSection.appendChild(_dslPreviewEl);

    body.appendChild(seqSection);

    // Section: Action buttons
    const actionsSection = _el('div', 'pb-section pb-actions');
    _searchBtn = _el('button', 'pb-btn pb-btn-primary');
    _searchBtn.id = 'pbSearchBtn';
    _searchBtn.textContent = 'Search';
    _searchBtn.disabled = true;

    _cancelBtn = _el('button', 'pb-btn');
    _cancelBtn.id = 'pbCancelBtn';
    _cancelBtn.textContent = 'Cancel';
    _cancelBtn.style.display = 'none';

    _clearBtn = _el('button', 'pb-btn');
    _clearBtn.id = 'pbClearBtn';
    _clearBtn.textContent = 'Clear';

    actionsSection.appendChild(_searchBtn);
    actionsSection.appendChild(_cancelBtn);
    actionsSection.appendChild(_clearBtn);
    body.appendChild(actionsSection);

    // Section: Progress (hidden by default)
    const progressSection = _el('div', 'pb-section pb-progress');
    progressSection.id = 'pbProgress';
    progressSection.style.display = 'none';
    progressSection.innerHTML = `
<div class="pb-progress-track"><div class="pb-progress-bar" id="pbProgressBar"></div></div>
<span class="pb-progress-label" id="pbProgressLabel">Searching\u2026</span>`;
    body.appendChild(progressSection);

    // Section: Results (hidden by default)
    const resultsSection = _el('div', 'pb-section pb-results');
    resultsSection.id = 'pbResults';
    resultsSection.style.display = 'none';
    body.appendChild(resultsSection);

    // Filter state is tracked as a plain boolean (_filterActive), not a hidden checkbox

    // Constraint popover (positioned absolutely within popup)
    _popoverEl = _el('div', 'pb-constraint-popover');
    _popoverEl.id = 'pbConstraintPopover';
    _popoverEl.style.display = 'none';
    _popupEl.appendChild(_popoverEl);

    // Store refs
    _progressEl       = progressSection;
    _progressBarEl    = progressSection.querySelector('#pbProgressBar');
    _progressLabelEl  = progressSection.querySelector('#pbProgressLabel');
    _resultsEl        = resultsSection;
}

// ─── Event wiring ─────────────────────────────────────────────────────────────

function _wirePopupEvents() {
    const titlebar = _popupEl.querySelector('.pb-titlebar');

    // Close button
    const closeBtn = _popupEl.querySelector('.pb-close');
    if (closeBtn) closeBtn.addEventListener('click', hidePatternBuilderPopup);

    // Drag to reposition
    if (titlebar) {
        titlebar.addEventListener('mousedown', _onTitlebarMousedown);
    }

    // Level radios
    _popupEl.querySelectorAll('input[name="pbLevel"]').forEach(radio => {
        _levelRadios[radio.value] = radio;
        radio.addEventListener('change', () => {
            if (radio.checked) {
                _currentLevel = parseInt(radio.value);
                _blocks = [];
                _fallbackDsl = null;
                _selectedBlockId = null;
                _closePopover();
                _renderPalette();
                _updatePresets(_currentLevel);
                _rebuild();
            }
        });
    });

    // Scope radios
    _popupEl.querySelectorAll('input[name="pbScope"]').forEach(radio => {
        _scopeRadios[radio.value] = radio;
    });

    // Time range radios
    _popupEl.querySelectorAll('input[name="pbTimeRange"]').forEach(radio => {
        _timeRangeRadios[radio.value] = radio;
    });

    // Preset select
    _presetSelect = _popupEl.querySelector('#pbPresetSelect');
    if (_presetSelect) {
        _updatePresets(1);
        _presetSelect.addEventListener('change', _onPresetChange);
    }

    // Clear pattern button
    const clearPatternBtn = _popupEl.querySelector('#pbClearPattern');
    if (clearPatternBtn) {
        clearPatternBtn.addEventListener('click', () => {
            _blocks = [];
            _fallbackDsl = null;
            _selectedBlockId = null;
            _closePopover();
            if (_presetSelect) _presetSelect.value = '';
            _rebuild();
        });
    }

    // Search button
    _searchBtn.addEventListener('click', _onSearch);

    // Cancel button
    _cancelBtn.addEventListener('click', () => {
        if (typeof _callbacks.onCancel === 'function') _callbacks.onCancel();
        _setSearching(false);
    });

    // Clear button
    _clearBtn.addEventListener('click', () => {
        _blocks = [];
        _fallbackDsl = null;
        _selectedBlockId = null;
        _closePopover();
        if (_presetSelect) _presetSelect.value = '';
        _filterActive = false;
        clearSearchResults();
        if (typeof _callbacks.onClear === 'function') _callbacks.onClear();
        _rebuild();
    });

    // Render initial palette
    _renderPalette();
    _rebuild();

    // Close popover when clicking outside (clean up previous listener on re-init)
    if (_docMousedownHandler) {
        document.removeEventListener('mousedown', _docMousedownHandler);
    }
    _docMousedownHandler = (e) => {
        if (_popoverEl && _popoverEl.style.display !== 'none') {
            if (!_popoverEl.contains(e.target) && !e.target.closest('.pb-seq-block') && !e.target.closest('.pb-seq-group')) {
                _closePopover();
            }
        }
        if (_groupCreatorEl && _groupCreatorEl.style.display !== 'none') {
            if (!_groupCreatorEl.contains(e.target) && !e.target.closest('.pb-symbol-group-btn')) {
                _closeGroupCreator();
            }
        }
    };
    document.addEventListener('mousedown', _docMousedownHandler);
}

// ─── Drag implementation ──────────────────────────────────────────────────────

function _onTitlebarMousedown(e) {
    if (e.button !== 0) return;
    const rect = _popupEl.getBoundingClientRect();
    _dragState = {
        offsetX: e.clientX - rect.left,
        offsetY: e.clientY - rect.top,
        startX: e.clientX,
        startY: e.clientY,
        hasMoved: false
    };
    document.addEventListener('mousemove', _onDragMove);
    document.addEventListener('mouseup', _onDragEnd);
    e.preventDefault();
}

function _onDragMove(e) {
    if (!_dragState) return;
    const dist = Math.hypot(e.clientX - _dragState.startX, e.clientY - _dragState.startY);
    if (dist > 5) {
        _dragState.hasMoved = true;
        const newLeft = Math.max(0, Math.min(window.innerWidth - 60, e.clientX - _dragState.offsetX));
        const newTop  = Math.max(0, Math.min(window.innerHeight - 40, e.clientY - _dragState.offsetY));
        _popupEl.style.left  = `${newLeft}px`;
        _popupEl.style.top   = `${newTop}px`;
        _popupEl.style.right = 'auto';
    }
}

function _onDragEnd() {
    _dragState = null;
    document.removeEventListener('mousemove', _onDragMove);
    document.removeEventListener('mouseup', _onDragEnd);
}

// ─── Preset handling ──────────────────────────────────────────────────────────

function _updatePresets(level) {
    if (!_presetSelect) return;
    const presets = getPresetsForLevel(level);
    _presetSelect.innerHTML = '<option value="">-- Select preset --</option>';
    for (const p of presets) {
        const opt = document.createElement('option');
        opt.value = p.pattern;
        opt.textContent = p.label;
        _presetSelect.appendChild(opt);
    }
    _presetSelect.value = '';
}

function _onPresetChange() {
    const pattern = _presetSelect.value;
    if (!pattern) return;

    const blocks = dslToBlocks(pattern);
    if (blocks === null) {
        // Disjunction — cannot represent visually; use fallback
        _blocks = [];
        _fallbackDsl = pattern;
        _selectedBlockId = null;
        _closePopover();
        _rebuild();
    } else {
        _blocks = blocks;
        _fallbackDsl = null;
        _selectedBlockId = null;
        _closePopover();
        _rebuild();
    }
}

// ─── Palette rendering ────────────────────────────────────────────────────────

function _renderPalette() {
    if (!_paletteEl) return;
    _paletteEl.innerHTML = '';

    const flags = LEVEL_PALETTE[_currentLevel] || LEVEL_PALETTE[1];
    for (const flagType of flags) {
        const btn = _el('button', 'pb-palette-block');
        btn.textContent = PALETTE_DISPLAY_LABEL[flagType] || flagType;
        btn.title = `Add ${flagType}`;
        btn.style.backgroundColor = FLAG_COLORS[flagType] || '#6c757d';
        btn.addEventListener('click', () => _addBlock(flagType));
        _paletteEl.appendChild(btn);
    }

    _renderSymbols();
}

function _renderSymbols() {
    const row = document.getElementById('pbSymbolsRow');
    if (!row) return;
    row.innerHTML = '';

    const symbols = [
        { key: '^', label: '^', title: 'Start anchor — match at start of flow' },
        { key: '$', label: '$', title: 'End anchor — match at end of flow' },
        { key: 'WILDCARD', label: '·', title: 'Wildcard — match any single event' },
    ];

    for (const sym of symbols) {
        const btn = _el('button', 'pb-symbol-btn');
        btn.textContent = sym.label;
        btn.title = sym.title;
        btn.addEventListener('click', () => _addBlock(sym.key));
        row.appendChild(btn);
    }

    // Group creator button
    const groupBtn = _el('button', 'pb-symbol-btn pb-symbol-group-btn');
    groupBtn.textContent = '( | )';
    groupBtn.title = 'Create a group with alternatives (A | B)';
    groupBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        _openGroupCreator(groupBtn);
    });
    row.appendChild(groupBtn);
}

// ─── Group creator ────────────────────────────────────────────────────────────

let _groupAlternatives = [[], []]; // 2 empty alternatives by default

function _openGroupCreator(anchorEl) {
    if (!_groupCreatorEl) return;
    _groupAlternatives = [[], []];
    _renderGroupCreator();

    // Position below the anchor button
    const anchorRect = anchorEl.getBoundingClientRect();
    const popupRect = _popupEl.getBoundingClientRect();
    const relTop = anchorRect.bottom - popupRect.top + 6;
    const relLeft = anchorRect.left - popupRect.left;
    const maxLeft = popupRect.width - 280;
    _groupCreatorEl.style.top = `${relTop}px`;
    _groupCreatorEl.style.left = `${Math.max(4, Math.min(maxLeft, relLeft))}px`;
    _groupCreatorEl.style.display = 'block';
}

function _closeGroupCreator() {
    if (_groupCreatorEl) _groupCreatorEl.style.display = 'none';
}

function _renderGroupCreator() {
    if (!_groupCreatorEl) return;
    _groupCreatorEl.innerHTML = '';

    const title = _el('div', 'pb-gc-title');
    title.textContent = 'Create Group (A | B)';
    _groupCreatorEl.appendChild(title);

    // Render each alternative row
    _groupAlternatives.forEach((altBlocks, altIdx) => {
        const altRow = _el('div', 'pb-group-alt-row');

        // Label
        const label = _el('span', 'pb-group-alt-label');
        label.textContent = `Alt ${altIdx + 1}:`;
        altRow.appendChild(label);

        // Current pills in this alternative
        const pillsArea = _el('div', 'pb-group-alt-pills');
        if (altBlocks.length === 0) {
            const hint = _el('span', 'pb-group-alt-hint');
            hint.textContent = 'click flags below';
            pillsArea.appendChild(hint);
        } else {
            altBlocks.forEach((subBlock, subIdx) => {
                if (subIdx > 0) {
                    const arrow = _el('span', 'pb-group-alt-arrow');
                    arrow.textContent = '→';
                    pillsArea.appendChild(arrow);
                }
                const pill = _el('span', 'pb-group-alt-pill');
                pill.style.backgroundColor = FLAG_COLORS[subBlock.flagType] || '#6c757d';
                pill.textContent = PALETTE_DISPLAY_LABEL[subBlock.flagType] || subBlock.flagType;
                pill.title = 'Click to remove';
                pill.addEventListener('click', () => {
                    _groupAlternatives[altIdx].splice(subIdx, 1);
                    _renderGroupCreator();
                });
                pillsArea.appendChild(pill);
            });
        }
        altRow.appendChild(pillsArea);

        // Remove alternative button (only if > 2)
        if (_groupAlternatives.length > 2) {
            const removeAlt = _el('button', 'pb-group-alt-remove');
            removeAlt.textContent = '×';
            removeAlt.title = 'Remove this alternative';
            removeAlt.addEventListener('click', () => {
                _groupAlternatives.splice(altIdx, 1);
                _renderGroupCreator();
            });
            altRow.appendChild(removeAlt);
        }

        _groupCreatorEl.appendChild(altRow);

        // Mini palette for this alternative
        const miniPalette = _el('div', 'pb-group-alt-palette');
        const flags = LEVEL_PALETTE[_currentLevel] || LEVEL_PALETTE[1];
        for (const flagType of flags) {
            const btn = _el('button', 'pb-group-alt-flag-btn');
            btn.textContent = PALETTE_DISPLAY_LABEL[flagType] || flagType;
            btn.style.backgroundColor = FLAG_COLORS[flagType] || '#6c757d';
            btn.title = flagType;
            btn.addEventListener('click', () => {
                _groupAlternatives[altIdx].push({
                    id: _nextId(),
                    flagType,
                    negated: false,
                    quantifier: null,
                    constraints: []
                });
                _renderGroupCreator();
            });
            miniPalette.appendChild(btn);
        }
        // Also add wildcard to mini palette
        const wcBtn = _el('button', 'pb-group-alt-flag-btn');
        wcBtn.textContent = '·';
        wcBtn.style.backgroundColor = FLAG_COLORS['WILDCARD'];
        wcBtn.title = 'WILDCARD';
        wcBtn.addEventListener('click', () => {
            _groupAlternatives[altIdx].push({
                id: _nextId(),
                flagType: 'WILDCARD',
                negated: false,
                quantifier: null,
                constraints: []
            });
            _renderGroupCreator();
        });
        miniPalette.appendChild(wcBtn);

        _groupCreatorEl.appendChild(miniPalette);
    });

    // Add Alternative button (max 4)
    if (_groupAlternatives.length < 4) {
        const addAltBtn = _el('button', 'pb-group-add-alt-btn');
        addAltBtn.textContent = '+ Add Alternative';
        addAltBtn.addEventListener('click', () => {
            _groupAlternatives.push([]);
            _renderGroupCreator();
        });
        _groupCreatorEl.appendChild(addAltBtn);
    }

    // Action buttons row
    const actions = _el('div', 'pb-gc-actions');

    const createBtn = _el('button', 'pb-btn pb-btn-primary');
    createBtn.textContent = 'Create';
    createBtn.disabled = _groupAlternatives.some(alt => alt.length === 0);
    createBtn.addEventListener('click', () => {
        // Filter out empty alternatives
        const validAlts = _groupAlternatives.filter(alt => alt.length > 0);
        if (validAlts.length < 2) return;

        const groupBlock = {
            id: _nextId(),
            flagType: 'GROUP',
            negated: false,
            quantifier: null,
            constraints: [],
            alternatives: validAlts
        };
        _blocks.push(groupBlock);
        _fallbackDsl = null;
        _closeGroupCreator();
        _rebuild();
    });

    const cancelBtn = _el('button', 'pb-btn');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', _closeGroupCreator);

    actions.appendChild(createBtn);
    actions.appendChild(cancelBtn);
    _groupCreatorEl.appendChild(actions);
}

// ─── Block management ─────────────────────────────────────────────────────────

function _addBlock(flagType) {
    const block = {
        id: _nextId(),
        flagType,
        negated: false,
        quantifier: null,
        constraints: []
    };
    _blocks.push(block);
    _fallbackDsl = null;
    _rebuild();
}

function _removeBlock(blockId) {
    _blocks = _blocks.filter(b => b.id !== blockId);
    if (_selectedBlockId === blockId) {
        _selectedBlockId = null;
        _closePopover();
    }
    _rebuild();
}

function _updateBlock(blockId, changes) {
    const block = _blocks.find(b => b.id === blockId);
    if (!block) return;
    Object.assign(block, changes);
    _rebuild();
}

// ─── Sequence rendering ───────────────────────────────────────────────────────

function _renderSequence() {
    _sequenceEl.innerHTML = '';

    // If fallback DSL (disjunction preset), show readonly text field
    if (_fallbackDsl) {
        const ta = _el('textarea', 'pb-fallback-dsl');
        ta.readOnly = true;
        ta.rows = 2;
        ta.value = _fallbackDsl;
        ta.title = 'This preset uses OR logic and cannot be edited visually';
        _sequenceEl.appendChild(ta);
        return;
    }

    if (_blocks.length === 0) {
        const hint = _el('span', 'pb-sequence-hint');
        hint.textContent = 'Click flags above to build a pattern';
        _sequenceEl.appendChild(hint);
        return;
    }

    _blocks.forEach((block, idx) => {
        // Arrow before block (except first)
        if (idx > 0) {
            const arrow = _el('span', 'pb-seq-arrow');
            arrow.textContent = '→';
            const arrowItem = _el('div', 'pb-seq-item');
            arrowItem.appendChild(arrow);
            _sequenceEl.appendChild(arrowItem);
        }

        const item = _el('div', 'pb-seq-item');
        const pill = block.flagType === 'GROUP'
            ? _createGroupPill(block)
            : _createSequencePill(block);
        item.appendChild(pill);
        _sequenceEl.appendChild(item);
    });
}

function _createSequencePill(block) {
    const color = FLAG_COLORS[block.flagType] || '#6c757d';
    const pill = _el('div', 'pb-seq-block');
    pill.style.backgroundColor = color;
    pill.dataset.blockId = block.id;

    // Negated: dashed red border
    if (block.negated) pill.classList.add('pb-negated');

    // Selected: blue ring
    if (_selectedBlockId === block.id) pill.classList.add('pb-selected');

    // Label text (with ! prefix if negated)
    const label = (block.negated ? '!' : '') + (PALETTE_DISPLAY_LABEL[block.flagType] || block.flagType);
    pill.textContent = label;

    // Remove button (shown on hover via CSS)
    const removeBtn = _el('button', 'pb-remove-btn');
    removeBtn.textContent = '✕';
    removeBtn.title = 'Remove';
    removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        _removeBlock(block.id);
    });
    pill.appendChild(removeBtn);

    // Quantifier badge
    if (block.quantifier) {
        const badge = _el('span', 'pb-quant-badge');
        badge.textContent = _quantifierLabel(block.quantifier);
        pill.appendChild(badge);
    }

    // Click to open constraint popover
    pill.addEventListener('click', (e) => {
        e.stopPropagation();
        if (_selectedBlockId === block.id) {
            _selectedBlockId = null;
            _closePopover();
            _rebuild();
        } else {
            _selectedBlockId = block.id;
            _rebuild(); // Re-render destroys old pill DOM nodes
            // Query the freshly-rendered pill (dataset.blockId → data-block-id in DOM)
            const freshPill = _sequenceEl.querySelector(`[data-block-id="${block.id}"]`);
            _openPopover(block, freshPill || pill);
        }
    });

    return pill;
}

/**
 * Create a visual GROUP pill showing alternatives with colored sub-pills.
 * The group is treated as one opaque unit — sub-pills are read-only.
 */
function _createGroupPill(block) {
    const group = _el('div', 'pb-seq-group');
    group.dataset.blockId = block.id;

    // Negated: dashed red border
    if (block.negated) group.classList.add('pb-negated');

    // Selected: blue ring
    if (_selectedBlockId === block.id) group.classList.add('pb-selected');

    // Render each alternative, separated by pipe
    block.alternatives.forEach((altBlocks, altIdx) => {
        if (altIdx > 0) {
            const pipe = _el('span', 'pb-seq-group-pipe');
            pipe.textContent = '|';
            group.appendChild(pipe);
        }

        altBlocks.forEach((subBlock, subIdx) => {
            if (subIdx > 0) {
                const arrow = _el('span', 'pb-seq-group-arrow');
                arrow.textContent = '→';
                group.appendChild(arrow);
            }

            const subColor = FLAG_COLORS[subBlock.flagType] || '#6c757d';
            const subPill = _el('span', 'pb-seq-group-pill');
            subPill.style.backgroundColor = subColor;
            const subLabel = PALETTE_DISPLAY_LABEL[subBlock.flagType] || subBlock.flagType;
            subPill.textContent = subBlock.negated ? `!${subLabel}` : subLabel;
            if (subBlock.quantifier) {
                subPill.textContent += _quantifierLabel(subBlock.quantifier);
            }
            group.appendChild(subPill);
        });
    });

    // Remove button
    const removeBtn = _el('button', 'pb-remove-btn');
    removeBtn.textContent = '✕';
    removeBtn.title = 'Remove';
    removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        _removeBlock(block.id);
    });
    group.appendChild(removeBtn);

    // Quantifier badge
    if (block.quantifier) {
        const badge = _el('span', 'pb-quant-badge');
        badge.textContent = _quantifierLabel(block.quantifier);
        group.appendChild(badge);
    }

    // Click to open popover (quantifier + negation only)
    group.addEventListener('click', (e) => {
        e.stopPropagation();
        if (_selectedBlockId === block.id) {
            _selectedBlockId = null;
            _closePopover();
            _rebuild();
        } else {
            _selectedBlockId = block.id;
            _rebuild();
            const freshGroup = _sequenceEl.querySelector(`[data-block-id="${block.id}"]`);
            _openPopover(block, freshGroup || group);
        }
    });

    return group;
}

function _quantifierLabel(q) {
    if (!q) return '';
    switch (q.type) {
        case 'plus':     return '+';
        case 'optional': return '?';
        case 'exact':    return `{${q.min}}`;
        case 'range':    return q.max === null ? `{${q.min},}` : `{${q.min},${q.max}}`;
        default:         return '';
    }
}

// ─── DSL preview ──────────────────────────────────────────────────────────────

function _updateDslPreview() {
    if (!_dslPreviewEl) return;

    let dsl = '';
    if (_fallbackDsl) {
        dsl = _fallbackDsl;
    } else {
        dsl = blocksToDsl(_blocks);
    }

    if (!dsl) {
        _dslPreviewEl.innerHTML = '<span class="pb-dsl-placeholder">DSL preview</span>';
        _dslPreviewEl.className = 'pb-dsl-preview';
        _searchBtn.disabled = true;
        return;
    }

    _dslPreviewEl.textContent = dsl;

    const validation = validatePattern(dsl);
    if (validation.valid) {
        _dslPreviewEl.className = 'pb-dsl-preview pb-dsl-valid';
        _searchBtn.disabled = false;
    } else {
        _dslPreviewEl.className = 'pb-dsl-preview pb-dsl-invalid';
        _searchBtn.disabled = true;
    }
}

// ─── Main update function ─────────────────────────────────────────────────────

function _rebuild() {
    _renderSequence();
    _updateDslPreview();
}

// ─── Constraint popover ───────────────────────────────────────────────────────

function _openPopover(block, anchorEl) {
    if (!_popoverEl) return;

    _popoverEl.innerHTML = '';

    // Determine which sections to show based on block type
    const isAnchor = block.flagType === '$' || block.flagType === '^';
    const isGroup = block.flagType === 'GROUP';
    const showQuantifier = !isAnchor;
    const showDirectionAndTiming = !isAnchor && !isGroup;

    // Title
    const title = _el('div', 'pb-popover-title');
    const displayName = isGroup ? 'Group (…|…)' : (isAnchor ? (block.flagType === '^' ? 'Start Anchor (^)' : 'End Anchor ($)') : block.flagType);
    title.textContent = `Configure: ${displayName}`;
    _popoverEl.appendChild(title);

    // ── Quantifier section (hidden for anchors ^ and $) ──
    if (!showQuantifier) {
        // Skip straight to negation for anchors
    } else {
    const quantSection = _el('div', 'pb-popover-section');
    const quantLabel = _el('div', 'pb-popover-section-label');
    quantLabel.textContent = 'Repeat';
    quantSection.appendChild(quantLabel);

    const qType = block.quantifier ? block.quantifier.type : 'once';
    const quantOptions = [
        { value: 'once',     label: 'Once (default)' },
        { value: 'plus',     label: 'One or more (+)' },
        { value: 'optional', label: 'Optional (?)' },
        { value: 'range',    label: 'Repeat {n,m}' },
    ];

    let rangeRow;

    for (const opt of quantOptions) {
        const row = _el('label', 'pb-popover-radio-row');
        const radio = document.createElement('input');
        radio.type = 'radio';
        radio.name = `pbQuant_${block.id}`;
        radio.value = opt.value;
        if (qType === opt.value || (opt.value === 'exact' && qType === 'exact')) {
            radio.checked = true;
        }
        // 'once' maps to no quantifier
        if (opt.value === 'once' && !block.quantifier) radio.checked = true;
        row.appendChild(radio);
        row.append(` ${opt.label}`);
        quantSection.appendChild(row);

        radio.addEventListener('change', () => {
            if (!radio.checked) return;
            if (opt.value === 'once') {
                _updateBlock(block.id, { quantifier: null });
            } else if (opt.value === 'plus') {
                _updateBlock(block.id, { quantifier: { type: 'plus', min: 1, max: null } });
            } else if (opt.value === 'optional') {
                _updateBlock(block.id, { quantifier: { type: 'optional', min: 0, max: 1 } });
            } else if (opt.value === 'range') {
                _updateBlock(block.id, { quantifier: { type: 'range', min: 1, max: null } });
            }
            // Show/hide range inputs
            if (rangeRow) {
                rangeRow.style.display = opt.value === 'range' ? 'flex' : 'none';
            }
        });
    }

    // Range inputs (shown only for 'range' type)
    rangeRow = _el('div', 'pb-popover-range-row');
    rangeRow.style.display = (qType === 'range' || qType === 'exact') ? 'flex' : 'none';

    const minInput = document.createElement('input');
    minInput.type = 'number';
    minInput.min = '0';
    minInput.value = block.quantifier?.min ?? 1;
    minInput.placeholder = 'min';
    minInput.title = 'Minimum repetitions';

    const maxInput = document.createElement('input');
    maxInput.type = 'number';
    maxInput.min = '0';
    maxInput.value = (block.quantifier?.max !== null && block.quantifier?.max !== undefined && block.quantifier?.max !== Infinity)
        ? block.quantifier.max
        : '';
    maxInput.placeholder = 'max (blank=∞)';
    maxInput.title = 'Maximum repetitions (leave blank for unlimited)';

    const updateRange = () => {
        const min = parseInt(minInput.value);
        if (isNaN(min) || min < 0) return;
        const maxVal = maxInput.value.trim() ? parseInt(maxInput.value) : null;
        _updateBlock(block.id, { quantifier: { type: 'range', min, max: maxVal } });
    };

    minInput.addEventListener('change', updateRange);
    maxInput.addEventListener('change', updateRange);

    rangeRow.append('Min: ', minInput, ' Max: ', maxInput);
    quantSection.appendChild(rangeRow);
    _popoverEl.appendChild(quantSection);
    } // end showQuantifier

    // ── Direction section (Level 1 only, not for $ or GROUP) ──
    if (showDirectionAndTiming && _currentLevel === 1) {
        const dirSection = _el('div', 'pb-popover-section');
        const dirLabel = _el('div', 'pb-popover-section-label');
        dirLabel.textContent = 'Direction';
        dirSection.appendChild(dirLabel);

        const currentDir = _getConstraintVal(block, 'dir') || 'any';
        const dirOptions = [
            { value: 'any',  label: 'Any' },
            { value: 'out',  label: 'Outbound (dir=out)' },
            { value: 'in',   label: 'Inbound (dir=in)' },
        ];
        for (const opt of dirOptions) {
            const row = _el('label', 'pb-popover-radio-row');
            const radio = document.createElement('input');
            radio.type = 'radio';
            radio.name = `pbDir_${block.id}`;
            radio.value = opt.value;
            if (currentDir === opt.value) radio.checked = true;
            row.appendChild(radio);
            row.append(` ${opt.label}`);
            dirSection.appendChild(row);

            radio.addEventListener('change', () => {
                if (!radio.checked) return;
                if (opt.value === 'any') {
                    _removeConstraint(block.id, 'dir');
                } else {
                    _setConstraint(block.id, 'dir', '=', opt.value);
                }
            });
        }
        _popoverEl.appendChild(dirSection);

        // ── Timing section (Level 1 only) ──
        const timingSection = _el('div', 'pb-popover-section');
        const timingLabel = _el('div', 'pb-popover-section-label');
        timingLabel.textContent = 'Timing (dt)';
        timingSection.appendChild(timingLabel);

        const timingRow = _el('div', 'pb-popover-row');
        const currentDt = _getConstraintEntry(block, 'dt') || _getConstraintEntry(block, 'deltaTime');
        const opSelect = document.createElement('select');
        const ops = ['<', '<=', '=', '>=', '>'];
        for (const op of ops) {
            const o = document.createElement('option');
            o.value = op;
            o.textContent = op;
            if (currentDt && currentDt.op === op) o.selected = true;
            opSelect.appendChild(o);
        }
        const dtInput = document.createElement('input');
        dtInput.type = 'text';
        dtInput.placeholder = 'e.g. 50ms or 1s';
        dtInput.value = currentDt ? currentDt.val : '';
        dtInput.title = 'Delta time constraint (e.g. 50ms, 1s, 500us)';

        const updateTiming = () => {
            const val = dtInput.value.trim();
            _removeConstraint(block.id, 'dt');
            _removeConstraint(block.id, 'deltaTime');
            if (val) {
                _setConstraint(block.id, 'dt', opSelect.value, val);
            }
        };
        opSelect.addEventListener('change', updateTiming);
        dtInput.addEventListener('change', updateTiming);

        timingRow.appendChild(opSelect);
        timingRow.appendChild(dtInput);
        timingSection.appendChild(timingRow);
        _popoverEl.appendChild(timingSection);
    }

    // ── Negation ──
    const negSection = _el('div', 'pb-popover-section');
    const negLabel = _el('label', 'pb-popover-checkbox-row');
    const negCheck = document.createElement('input');
    negCheck.type = 'checkbox';
    negCheck.checked = !!block.negated;
    negCheck.addEventListener('change', () => {
        _updateBlock(block.id, { negated: negCheck.checked });
    });
    negLabel.appendChild(negCheck);
    negLabel.append(' NOT this event (!prefix)');
    negSection.appendChild(negLabel);
    _popoverEl.appendChild(negSection);

    // ── Done button ──
    const doneBtn = _el('button', 'pb-popover-done-btn');
    doneBtn.textContent = 'Done';
    doneBtn.addEventListener('click', () => {
        _selectedBlockId = null;
        _closePopover();
        _rebuild();
    });
    _popoverEl.appendChild(doneBtn);

    // Position the popover below the block pill
    _positionPopover(anchorEl);
    _popoverEl.style.display = 'block';
}

function _positionPopover(anchorEl) {
    if (!_popoverEl || !anchorEl) return;

    const anchorRect = anchorEl.getBoundingClientRect();
    const popupRect  = _popupEl.getBoundingClientRect();
    const popoverH   = 280; // estimated height before render

    // Position relative to the popup element
    const relTop  = anchorRect.bottom - popupRect.top + 6;
    const relLeft = anchorRect.left   - popupRect.left;

    // Clamp horizontally
    const maxLeft = popupRect.width - 228;
    const clampedLeft = Math.max(4, Math.min(maxLeft, relLeft));

    // Flip above if too close to bottom
    const flipThreshold = popupRect.height - 60;
    if (relTop + popoverH > flipThreshold) {
        const relTopFlipped = anchorRect.top - popupRect.top - popoverH - 6;
        _popoverEl.style.top = `${Math.max(40, relTopFlipped)}px`;
    } else {
        _popoverEl.style.top = `${relTop}px`;
    }

    _popoverEl.style.left = `${clampedLeft}px`;
}

function _closePopover() {
    if (_popoverEl) _popoverEl.style.display = 'none';
    _selectedBlockId = null;
}

// ─── Constraint helpers ───────────────────────────────────────────────────────

function _getConstraintVal(block, key) {
    const c = block.constraints.find(c => c.key === key);
    return c ? c.val : null;
}

function _getConstraintEntry(block, key) {
    return block.constraints.find(c => c.key === key) || null;
}

function _setConstraint(blockId, key, op, val) {
    const block = _blocks.find(b => b.id === blockId);
    if (!block) return;
    const existing = block.constraints.findIndex(c => c.key === key);
    if (existing >= 0) {
        block.constraints[existing] = { key, op, val };
    } else {
        block.constraints.push({ key, op, val });
    }
    _rebuild();
}

function _removeConstraint(blockId, key) {
    const block = _blocks.find(b => b.id === blockId);
    if (!block) return;
    block.constraints = block.constraints.filter(c => c.key !== key);
    _rebuild();
}

// ─── Search ───────────────────────────────────────────────────────────────────

async function _onSearch() {
    const dsl = _fallbackDsl || blocksToDsl(_blocks);
    if (!dsl) return;

    const validation = validatePattern(dsl);
    if (!validation.valid) return;

    const level = _getSelectedLevel();
    const scope = _getSelectedScope();
    const timeRange = _getSelectedTimeRange();

    if (typeof _callbacks.onSearch === 'function') {
        _setSearching(true);
        try {
            await _callbacks.onSearch(dsl, level, scope, timeRange);
        } finally {
            _setSearching(false);
        }
    }
}

function _setSearching(active) {
    if (_searchBtn) _searchBtn.style.display = active ? 'none' : '';
    if (_cancelBtn) _cancelBtn.style.display = active ? '' : 'none';
    if (!active) hideSearchProgress();
}

// ─── Selection helpers ────────────────────────────────────────────────────────

function _getSelectedLevel() {
    for (const [val, radio] of Object.entries(_levelRadios)) {
        if (radio.checked) return parseInt(val);
    }
    return 1;
}

function _getSelectedScope() {
    for (const [val, radio] of Object.entries(_scopeRadios)) {
        if (radio.checked) return val;
    }
    return 'selected';
}

function _getSelectedTimeRange() {
    for (const [val, radio] of Object.entries(_timeRangeRadios)) {
        if (radio.checked) return val;
    }
    return 'view';
}

// ─── Status indicator ─────────────────────────────────────────────────────────

function _updateStatusIndicator(matchCount) {
    const statusEl = document.getElementById('patternBuilderStatus');
    if (!statusEl) return;
    if (matchCount === null || matchCount === undefined) {
        statusEl.textContent = '';
    } else {
        statusEl.textContent = `${matchCount.toLocaleString()} matches`;
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function _el(tag, classes) {
    const parts = tag.split('.');
    const el = document.createElement(parts[0] || 'div');
    if (classes) {
        classes.trim().split(/\s+/).forEach(c => { if (c) el.classList.add(c); });
    }
    return el;
}

function _esc(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

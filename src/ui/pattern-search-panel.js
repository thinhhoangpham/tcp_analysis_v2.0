// src/ui/pattern-search-panel.js
// Thin shim: delegates all calls to the floating visual pattern builder popup.
// Preserves the same export signatures so tcp-analysis.js requires zero changes.

import {
    initPatternBuilderPopup,
    showSearchProgress  as _showProgress,
    hideSearchProgress  as _hideProgress,
    showSearchResults   as _showResults,
    clearSearchResults  as _clearResults,
} from './pattern-builder-popup.js';

/**
 * Initialize the pattern search UI.
 * The containerEl argument is accepted for signature compatibility but is unused —
 * the popup is a fixed-position overlay, not embedded in the control panel.
 *
 * @param {HTMLElement} containerEl - Ignored (kept for API compatibility)
 * @param {Object} options
 * @param {Function} options.onSearch
 * @param {Function} options.onCancel
 * @param {Function} options.onClear
 * @param {Function} options.onFilterToggle
 * @param {Function} options.onSelectMatchedIPs
 */
export function initPatternSearchUI(containerEl, options) {
    initPatternBuilderPopup(options);
}

export function showSearchProgress(pct, label) { _showProgress(pct, label); }
export function hideSearchProgress()            { _hideProgress(); }
export function showSearchResults(results, onViewFlows, onSelectMatchedIPs) {
    _showResults(results, onViewFlows, onSelectMatchedIPs);
}
export function clearSearchResults()            { _clearResults(); }

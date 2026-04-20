// src/rendering/canvas-flow-renderer.js
// Canvas-based renderer for flow lozenges + IP labels.
// Draws both in the same coordinate system — no alignment issues.
// Only renders visible rows (~30 at a time) for performance.

function hexToRGB(hex) {
    if (!hex || hex.length < 4) return 'rgb(173,181,189)';
    hex = hex.replace('#', '');
    if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
    return `rgb(${parseInt(hex.slice(0,2),16)},${parseInt(hex.slice(2,4),16)},${parseInt(hex.slice(4,6),16)})`;
}

export class CanvasFlowRenderer {
    constructor(container, margin, chartWidth) {
        this.margin = margin;
        this.chartWidth = chartWidth;
        this.items = [];       // all lozenge items sorted by Y
        this.itemsByIP = new Map();
        this.ipOrder = [];     // ordered IP list
        this.ipPositions = null; // Map<ip, yPx>
        this.colorMap = null;
        this.hScale = null;
        this.minHeight = 4;
        this.maxHeight = 20;
        this.individualHeight = 6;

        // Create canvas — fills the scroll container viewport
        this.canvas = document.createElement('canvas');
        this.canvas.style.position = 'absolute';
        this.canvas.style.left = '0px';
        this.canvas.style.top = '0px';
        this.canvas.style.pointerEvents = 'none';
        this.canvas.style.zIndex = '1';
        container.style.position = 'relative';
        container.appendChild(this.canvas);

        this.ctx = this.canvas.getContext('2d');
        this.container = container;
        this._lastHit = null;
        this.showGroundTruth = false;
        this.groundTruthEvents = [];
        this.gtBySourceIP = new Map();
        this.eventColors = {};
    }

    /**
     * Set IP row layout.
     */
    setLayout(ipOrder, ipPositions, rowGap) {
        this.ipOrder = ipOrder;
        this.ipPositions = ipPositions;
        this.rowGap = rowGap || 30;
    }

    /**
     * Set ground truth events for overlay rendering.
     * @param {Array} events - ground truth events with source, destination, startTimeMicroseconds, stopTimeMicroseconds, eventType
     * @param {Object} eventColors - eventType → hex color mapping
     */
    setGroundTruth(events, eventColors) {
        this.groundTruthEvents = events || [];
        this.eventColors = eventColors || {};
        // Index by source IP for fast per-row lookup
        this.gtBySourceIP = new Map();
        for (const evt of this.groundTruthEvents) {
            if (!evt.source) continue;
            if (!this.gtBySourceIP.has(evt.source)) this.gtBySourceIP.set(evt.source, []);
            this.gtBySourceIP.get(evt.source).push(evt);
        }
    }

    /**
     * Toggle ground truth overlay visibility.
     */
    setShowGroundTruth(show) {
        this.showGroundTruth = !!show;
    }

    /**
     * Set lozenge data.
     */
    setData(items, colorMap, hScale, { minHeight = 4, maxHeight = 20, individualHeight = 6 } = {}) {
        this.colorMap = colorMap;
        this.hScale = hScale;
        this.minHeight = minHeight;
        this.maxHeight = maxHeight;
        this.individualHeight = individualHeight;

        // Index items by initiator IP for fast per-row lookup
        this.itemsByIP = new Map();
        for (const d of items) {
            const ip = d.initiator || d.src_ip;
            if (!ip) continue;
            if (!this.itemsByIP.has(ip)) this.itemsByIP.set(ip, []);
            this.itemsByIP.get(ip).push(d);
        }
        this.items = items;
    }

    /**
     * Render visible rows (labels + lozenges).
     */
    render(xScale, scrollTop, viewportHeight) {
        const ctx = this.ctx;
        if (!ctx || !this.ipPositions) return;

        const dpr = window.devicePixelRatio || 1;
        const fullWidth = this.margin.left + this.chartWidth + this.margin.right;
        const ch = viewportHeight;

        // Resize canvas to viewport
        const cw = Math.round(fullWidth * dpr);
        const chPx = Math.round(ch * dpr);
        if (this.canvas.width !== cw || this.canvas.height !== chPx) {
            this.canvas.width = cw;
            this.canvas.height = chPx;
            this.canvas.style.width = fullWidth + 'px';
            this.canvas.style.height = ch + 'px';
        }

        // Position canvas at current scroll
        this.canvas.style.top = scrollTop + 'px';

        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, fullWidth, ch);

        const marginTop = this.margin.top;
        const marginLeft = this.margin.left;

        // Determine visible Y range
        const yMin = scrollTop - marginTop - this.rowGap;
        const yMax = scrollTop - marginTop + viewportHeight + this.rowGap;

        // Draw each visible IP row
        ctx.font = '12px monospace';
        ctx.textBaseline = 'middle';

        for (const ip of this.ipOrder) {
            const yPos = this.ipPositions.get(ip);
            if (yPos === undefined) continue;
            if (yPos < yMin || yPos > yMax) continue;

            // Screen Y for this row
            const screenY = yPos + marginTop - scrollTop;

            // Draw lozenges for this IP
            const rowItems = this.itemsByIP.get(ip);
            if (!rowItems) continue;

            for (const d of rowItems) {
                const xStart = d.binStart ?? d.startTime ?? d.binCenter ?? 0;
                const xEnd = d.binEnd ?? d.endTime ?? xStart;
                const x = xScale(xStart) + marginLeft;
                const w = Math.max(4, xScale(xEnd) - xScale(xStart));
                const h = this._getHeight(d);
                const y = screenY - h / 2;
                const color = this._getColor(d);
                const r = h / 2;

                ctx.fillStyle = color;
                if (r > 1 && w > 2) {
                    this._roundRect(ctx, x, y, w, h, Math.min(r, w / 2));
                    ctx.fill();
                } else {
                    ctx.fillRect(x, y, w, h);
                }
            }
        }

        // Draw ground truth overlays on source IP rows
        if (this.showGroundTruth && this.gtBySourceIP && xScale) {
            ctx.globalAlpha = 0.25;
            for (const ip of this.ipOrder) {
                const yPos = this.ipPositions.get(ip);
                if (yPos === undefined || yPos < yMin || yPos > yMax) continue;
                const events = this.gtBySourceIP.get(ip);
                if (!events) continue;
                const screenY = yPos + marginTop - scrollTop;
                for (const evt of events) {
                    const x1 = xScale(evt.startTimeMicroseconds);
                    const x2 = xScale(evt.stopTimeMicroseconds || evt.startTimeMicroseconds);
                    const x = Math.min(x1, x2) + marginLeft;
                    const w = Math.max(3, Math.abs(x2 - x1));
                    const color = this.eventColors[evt.eventType] || '#888';
                    ctx.fillStyle = color;
                    ctx.fillRect(x, screenY - this.rowGap / 2, w, this.rowGap);
                }
            }
            ctx.globalAlpha = 1.0;
        }

        // Draw hover label
        if (this._hoveredIP) {
            const hoverY = this.ipPositions.get(this._hoveredIP);
            if (hoverY !== undefined && hoverY >= yMin && hoverY <= yMax) {
                const sy = hoverY + marginTop - scrollTop;
                // Background
                ctx.font = '11px monospace';
                const tw = ctx.measureText(this._hoveredIP).width;
                ctx.fillStyle = 'rgba(0,0,0,0.75)';
                ctx.fillRect(marginLeft - tw - 18, sy - 8, tw + 12, 16);
                // Text
                ctx.fillStyle = '#fff';
                ctx.textAlign = 'right';
                ctx.textBaseline = 'middle';
                ctx.fillText(this._hoveredIP, marginLeft - 12, sy);
                // Row highlight
                ctx.fillStyle = 'rgba(77,171,247,0.12)';
                ctx.fillRect(marginLeft, sy - this.rowGap / 2, this.chartWidth, this.rowGap);
            }
        }
    }

    /**
     * Enable mouse hover for IP labels. Call once after canvas is created.
     */
    enableHover(xScale, getScrollTop) {
        this.canvas.style.pointerEvents = 'auto';
        this._xScale = xScale;
        this._getScrollTop = getScrollTop;

        this.canvas.addEventListener('mousemove', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const dpr = window.devicePixelRatio || 1;
            const mouseY = e.clientY - rect.top;
            const scrollTop = this._getScrollTop();
            const dataY = mouseY + scrollTop - this.margin.top;

            // Find closest IP row
            let closestIP = null;
            let closestDist = this.rowGap / 2;
            for (const ip of this.ipOrder) {
                const yPos = this.ipPositions.get(ip);
                if (yPos === undefined) continue;
                const dist = Math.abs(yPos - dataY);
                if (dist < closestDist) {
                    closestDist = dist;
                    closestIP = ip;
                }
            }

            if (closestIP !== this._hoveredIP) {
                this._hoveredIP = closestIP;
                this.render(this._xScale, scrollTop, this.canvas.clientHeight);
            }
        });

        this.canvas.addEventListener('mouseleave', () => {
            if (this._hoveredIP) {
                this._hoveredIP = null;
                this.render(this._xScale, this._getScrollTop(), this.canvas.clientHeight);
            }
        });
    }

    _getHeight(d) {
        if (!d.binned) return this.individualHeight;
        return this.hScale
            ? Math.max(this.minHeight, Math.min(this.maxHeight, this.hScale(d.count || 1)))
            : this.minHeight;
    }

    _getColor(d) {
        if (!this.colorMap) return 'rgb(173,181,189)';
        const ct = d.closeType || d.invalidReason;
        if (this.colorMap instanceof Map) {
            return this.colorMap.get(ct) || this.colorMap.get(d.invalidReason) || 'rgb(173,181,189)';
        }
        return this.colorMap[ct] || 'rgb(173,181,189)';
    }

    _roundRect(ctx, x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.lineTo(x + w - r, y);
        ctx.quadraticCurveTo(x + w, y, x + w, y + r);
        ctx.lineTo(x + w, y + h - r);
        ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
        ctx.lineTo(x + r, y + h);
        ctx.quadraticCurveTo(x, y + h, x, y + h - r);
        ctx.lineTo(x, y + r);
        ctx.quadraticCurveTo(x, y, x + r, y);
        ctx.closePath();
    }

    /**
     * Hit test for tooltip support.
     */
    hitTest(mouseX, mouseY, xScale, scrollTop) {
        const marginTop = this.margin.top;
        const marginLeft = this.margin.left;
        // Convert mouse position to data Y
        const dataY = mouseY + scrollTop - marginTop;
        const dataX = mouseX - marginLeft;

        for (const ip of this.ipOrder) {
            const yPos = this.ipPositions.get(ip);
            if (yPos === undefined) continue;
            if (Math.abs(yPos - dataY) > this.rowGap / 2) continue;

            const rowItems = this.itemsByIP.get(ip);
            if (!rowItems) continue;

            for (const d of rowItems) {
                const xStart = d.binStart ?? d.startTime ?? d.binCenter ?? 0;
                const xEnd = d.binEnd ?? d.endTime ?? xStart;
                const xPx = xScale(xStart);
                const wPx = Math.max(4, xScale(xEnd) - xScale(xStart));
                const h = this._getHeight(d);
                if (dataX >= xPx && dataX <= xPx + wPx && Math.abs(yPos - dataY) <= h / 2) {
                    return d;
                }
            }
            break; // Only check the closest row
        }
        return null;
    }

    resize(chartWidth) {
        this.chartWidth = chartWidth;
    }

    destroy() {
        if (this.canvas && this.canvas.parentElement) {
            this.canvas.parentElement.removeChild(this.canvas);
        }
        this.ctx = null;
    }
}

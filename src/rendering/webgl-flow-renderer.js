// src/rendering/webgl-flow-renderer.js
// WebGL-based flow lozenge renderer using regl.
// Renders all lozenges in a single instanced draw call — scales to ~1M shapes.
// API-compatible with CanvasFlowRenderer for drop-in replacement.

function parseColorToRGB(str) {
    if (!str) return [0.68, 0.71, 0.75];
    if (str[0] === '#') {
        let hex = str.slice(1);
        if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
        const n = parseInt(hex, 16);
        return [((n >> 16) & 0xff) / 255, ((n >> 8) & 0xff) / 255, (n & 0xff) / 255];
    }
    const m = str.match(/rgba?\s*\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)/);
    if (m) return [+m[1] / 255, +m[2] / 255, +m[3] / 255];
    return [0.68, 0.71, 0.75];
}

export class WebGLFlowRenderer {
    constructor(container, margin, chartWidth) {
        this.margin = margin;
        this.chartWidth = chartWidth;
        this.ipOrder = [];
        this.ipPositions = null;
        this.rowGap = 30;
        this.colorMap = null;
        this.hScale = null;
        this.minHeight = 4;
        this.maxHeight = 20;
        this.individualHeight = 6;
        this.items = [];
        this.itemsByIP = new Map();
        this.instanceCount = 0;
        this._hoveredIP = null;
        this.showGroundTruth = false;
        this.groundTruthEvents = [];
        this.gtBySourceIP = new Map();
        this.eventColors = {};

        // Main WebGL canvas for lozenges
        this.canvas = document.createElement('canvas');
        this.canvas.style.position = 'absolute';
        this.canvas.style.left = '0px';
        this.canvas.style.top = '0px';
        this.canvas.style.pointerEvents = 'none';
        this.canvas.style.zIndex = '1';

        // Overlay 2D canvas for ground truth + hover label (cheap, rarely redrawn)
        this.overlayCanvas = document.createElement('canvas');
        this.overlayCanvas.style.position = 'absolute';
        this.overlayCanvas.style.left = '0px';
        this.overlayCanvas.style.top = '0px';
        this.overlayCanvas.style.pointerEvents = 'none';
        this.overlayCanvas.style.zIndex = '2';

        container.style.position = 'relative';
        container.appendChild(this.canvas);
        container.appendChild(this.overlayCanvas);
        this.container = container;
        this.overlayCtx = this.overlayCanvas.getContext('2d');

        if (typeof createREGL === 'undefined') {
            console.error('[WebGLFlowRenderer] regl is not loaded. Add <script src="https://unpkg.com/regl@2.1.0/dist/regl.min.js"> to the HTML.');
            return;
        }

        this.regl = createREGL({
            canvas: this.canvas,
            attributes: { antialias: true, premultipliedAlpha: false },
            extensions: ['ANGLE_instanced_arrays'],
            optionalExtensions: ['OES_standard_derivatives']
        });
        this._hasDerivatives = !!this.regl.hasExtension('OES_standard_derivatives');

        // Shared unit-quad corners used by every instance
        this._cornerBuf = this.regl.buffer(new Float32Array([0,0, 1,0, 0,1, 1,1]));

        // Per-instance attribute buffers (filled in setData)
        this._timeStartBuf = this.regl.buffer({ length: 4, usage: 'dynamic' });
        this._timeWidthBuf = this.regl.buffer({ length: 4, usage: 'dynamic' });
        this._yPosBuf      = this.regl.buffer({ length: 4, usage: 'dynamic' });
        this._heightBuf    = this.regl.buffer({ length: 4, usage: 'dynamic' });
        this._colorBuf     = this.regl.buffer({ length: 12, usage: 'dynamic' });

        this.drawLozenges = this.regl({
            vert: `
                precision highp float;
                attribute vec2 corner;
                attribute float timeStart;
                attribute float timeWidth;
                attribute float yPos;
                attribute float height;
                attribute vec3 color;

                uniform float scaleX;
                uniform float offsetX;
                uniform float offsetY;
                uniform vec2 viewport;
                uniform float minWidth;

                varying vec3 vColor;
                varying vec2 vLocal;
                varying vec2 vHalfSize;

                void main() {
                    float pxStart = timeStart * scaleX + offsetX;
                    float pxWidth = max(minWidth, timeWidth * scaleX);
                    float pxX = pxStart + corner.x * pxWidth;
                    float pxY = (yPos + offsetY) - height * 0.5 + corner.y * height;

                    float clipX = (pxX / viewport.x) * 2.0 - 1.0;
                    float clipY = 1.0 - (pxY / viewport.y) * 2.0;

                    gl_Position = vec4(clipX, clipY, 0.0, 1.0);
                    vColor = color;
                    vHalfSize = vec2(pxWidth, height) * 0.5;
                    vLocal = (corner - 0.5) * 2.0 * vHalfSize;
                }
            `,
            frag: (this._hasDerivatives ? '#extension GL_OES_standard_derivatives : enable\n' : '') + `
                precision mediump float;
                varying vec3 vColor;
                varying vec2 vLocal;
                varying vec2 vHalfSize;

                void main() {
                    float r = min(vHalfSize.y, vHalfSize.x);
                    vec2 q = abs(vLocal) - (vHalfSize - r);
                    float d = length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r;
                    ${this._hasDerivatives
                        ? 'float aa = max(fwidth(d), 0.5); float alpha = 1.0 - smoothstep(-aa, aa, d);'
                        : 'float alpha = d > 0.0 ? 0.0 : 1.0;'}
                    if (alpha < 0.01) discard;
                    gl_FragColor = vec4(vColor, alpha);
                }
            `,
            attributes: {
                corner:    { buffer: this._cornerBuf, size: 2, type: 'float' },
                timeStart: { buffer: this._timeStartBuf, divisor: 1, size: 1, type: 'float', stride: 4 },
                timeWidth: { buffer: this._timeWidthBuf, divisor: 1, size: 1, type: 'float', stride: 4 },
                yPos:      { buffer: this._yPosBuf,      divisor: 1, size: 1, type: 'float', stride: 4 },
                height:    { buffer: this._heightBuf,    divisor: 1, size: 1, type: 'float', stride: 4 },
                color:     { buffer: this._colorBuf,     divisor: 1, size: 3, type: 'float', stride: 12 }
            },
            uniforms: {
                scaleX:   this.regl.prop('scaleX'),
                offsetX:  this.regl.prop('offsetX'),
                offsetY:  this.regl.prop('offsetY'),
                viewport: this.regl.prop('viewport'),
                minWidth: this.regl.prop('minWidth')
            },
            count: 4,
            primitive: 'triangle strip',
            instances: this.regl.prop('instances'),
            blend: {
                enable: true,
                func: { srcRGB: 'src alpha', srcAlpha: 1, dstRGB: 'one minus src alpha', dstAlpha: 1 }
            },
            depth: { enable: false }
        });
    }

    setLayout(ipOrder, ipPositions, rowGap) {
        this.ipOrder = ipOrder;
        this.ipPositions = ipPositions;
        this.rowGap = rowGap || 30;
        // Layout change invalidates per-instance yPos values — rebuild if data already loaded
        if (this.items && this.items.length) this._rebuildBuffers();
    }

    setGroundTruth(events, eventColors) {
        this.groundTruthEvents = events || [];
        this.eventColors = eventColors || {};
        this.gtBySourceIP = new Map();
        for (const evt of this.groundTruthEvents) {
            if (!evt.source) continue;
            if (!this.gtBySourceIP.has(evt.source)) this.gtBySourceIP.set(evt.source, []);
            this.gtBySourceIP.get(evt.source).push(evt);
        }
    }

    setShowGroundTruth(show) {
        this.showGroundTruth = !!show;
    }

    setData(items, colorMap, hScale, { minHeight = 4, maxHeight = 20, individualHeight = 6 } = {}) {
        console.log('[WebGLRenderer] setData called with', items?.length || 0, 'items');
        this.colorMap = colorMap;
        this.hScale = hScale;
        this.minHeight = minHeight;
        this.maxHeight = maxHeight;
        this.individualHeight = individualHeight;

        this.itemsByIP = new Map();
        for (const d of items) {
            const ip = d.initiator || d.src_ip;
            if (!ip) continue;
            if (!this.itemsByIP.has(ip)) this.itemsByIP.set(ip, []);
            this.itemsByIP.get(ip).push(d);
        }
        this.items = items;
        this._rebuildBuffers();
    }

    _rebuildBuffers() {
        if (!this.regl || !this.ipPositions) return;

        const items = this.items;
        const n = items.length;
        this.instanceCount = n;
        if (n === 0) return;

        // Bias timestamps by origin to keep values within float32 integer precision (~2^24).
        // Microsecond timestamps (~1.7e15) would otherwise lose all per-item precision when
        // uploaded as float32 attributes. Origin is kept as JS double; shader works in
        // "microseconds since origin".
        let minT = Infinity;
        for (let i = 0; i < n; i++) {
            const t = items[i].binStart ?? items[i].startTime ?? items[i].binCenter ?? 0;
            if (t < minT) minT = t;
        }
        this._timeOrigin = isFinite(minT) ? minT : 0;

        const timeStarts = new Float32Array(n);
        const timeWidths = new Float32Array(n);
        const yPositions = new Float32Array(n);
        const heights    = new Float32Array(n);
        const colors     = new Float32Array(n * 3);

        // Cache parsed colors per hex string — typically 8-15 unique colors
        const colorCache = new Map();
        const getRGB = (d) => {
            const key = (d.closeType || d.invalidReason || '_default');
            let rgb = colorCache.get(key);
            if (!rgb) {
                rgb = parseColorToRGB(this._getColorString(d));
                colorCache.set(key, rgb);
            }
            return rgb;
        };

        for (let i = 0; i < n; i++) {
            const d = items[i];
            const ip = d.initiator || d.src_ip;
            const yPos = this.ipPositions.get(ip);
            if (yPos === undefined) continue;

            const xStart = d.binStart ?? d.startTime ?? d.binCenter ?? 0;
            const xEnd   = d.binEnd   ?? d.endTime   ?? xStart;

            timeStarts[i] = xStart - this._timeOrigin;
            timeWidths[i] = Math.max(0, xEnd - xStart);
            yPositions[i] = yPos;
            heights[i]    = this._getHeight(d);

            const rgb = getRGB(d);
            colors[i * 3]     = rgb[0];
            colors[i * 3 + 1] = rgb[1];
            colors[i * 3 + 2] = rgb[2];
        }

        // In-place update: the draw command captured these buffer objects by reference,
        // so we must update their contents rather than replace the objects.
        this._timeStartBuf({ data: timeStarts, usage: 'dynamic' });
        this._timeWidthBuf({ data: timeWidths, usage: 'dynamic' });
        this._yPosBuf(     { data: yPositions, usage: 'dynamic' });
        this._heightBuf(   { data: heights,    usage: 'dynamic' });
        this._colorBuf(    { data: colors,     usage: 'dynamic' });

        // Diagnostic: sample a few values to confirm buffers are populated correctly in JS
        const midIdx = Math.floor(n / 2);
        console.log('[WebGLRenderer] buffer samples (n=' + n + '):',
            '\n  timeStarts[0,mid,last]=', timeStarts[0], timeStarts[midIdx], timeStarts[n-1],
            '\n  yPositions[0,mid,last]=', yPositions[0], yPositions[midIdx], yPositions[n-1],
            '\n  heights[0,mid,last]=', heights[0], heights[midIdx], heights[n-1],
            '\n  colors[0..5]=', colors[0], colors[1], colors[2], colors[3], colors[4], colors[5]);
    }

    render(xScale, scrollTop, viewportHeight) {
        if (!this.regl) return;
        if (!this._renderLogged) {
            console.log('[WebGLRenderer] render called, instances=', this.instanceCount,
                'scrollTop=', scrollTop, 'viewportH=', viewportHeight,
                'domain=', xScale?.domain?.(), 'range=', xScale?.range?.());
            this._renderLogged = true;
        }

        const dpr = window.devicePixelRatio || 1;
        const fullWidth = this.margin.left + this.chartWidth + this.margin.right;
        const ch = viewportHeight;

        // Resize main WebGL canvas
        const cwPx = Math.round(fullWidth * dpr);
        const chPx = Math.round(ch * dpr);
        if (this.canvas.width !== cwPx || this.canvas.height !== chPx) {
            this.canvas.width = cwPx;
            this.canvas.height = chPx;
            this.canvas.style.width = fullWidth + 'px';
            this.canvas.style.height = ch + 'px';
        }
        this.canvas.style.top = scrollTop + 'px';

        // Resize overlay canvas to match
        if (this.overlayCanvas.width !== cwPx || this.overlayCanvas.height !== chPx) {
            this.overlayCanvas.width = cwPx;
            this.overlayCanvas.height = chPx;
            this.overlayCanvas.style.width = fullWidth + 'px';
            this.overlayCanvas.style.height = ch + 'px';
        }
        this.overlayCanvas.style.top = scrollTop + 'px';

        this.regl.poll();
        this.regl.clear({ color: [0, 0, 0, 0], depth: 1 });

        if (this.instanceCount > 0 && xScale) {
            const [d0, d1] = xScale.domain();
            const [r0, r1] = xScale.range();
            const span = (d1 - d0) || 1;
            const scaleX = (r1 - r0) / span;
            // Since vertex attribute stores (timeStart - timeOrigin), adjust offset accordingly.
            // pxStart = (timeStart_us - timeOrigin) * scaleX + offsetX
            //        = timeStart_us * scaleX - timeOrigin * scaleX + offsetX
            // We want this to equal xScale(timeStart_us) + marginLeft = (timeStart_us - d0) * scaleX + r0 + marginLeft
            // => offsetX = (timeOrigin - d0) * scaleX + r0 + marginLeft
            const origin = this._timeOrigin || 0;
            const offsetX = (origin - d0) * scaleX + r0 + this.margin.left;
            const offsetY = this.margin.top - scrollTop;

            try {
                this.drawLozenges({
                    scaleX,
                    offsetX,
                    offsetY,
                    viewport: [fullWidth, ch],
                    minWidth: 4,
                    instances: this.instanceCount
                });
                if (!this._drawLogged) {
                    const gl = this.regl._gl;
                    console.log('[WebGLRenderer] draw complete. scaleX=', scaleX, 'offsetX=', offsetX, 'offsetY=', offsetY,
                        'canvas size=', this.canvas.width, 'x', this.canvas.height,
                        'GL error=', gl ? gl.getError() : 'n/a',
                        'first item timeStart_rel (sample)=', this._timeOrigin);
                    this._drawLogged = true;
                }
            } catch (err) {
                console.error('[WebGLRenderer] draw failed:', err);
            }
        }

        this._drawOverlay(xScale, scrollTop, viewportHeight, dpr);
    }

    _drawOverlay(xScale, scrollTop, viewportHeight, dpr) {
        const ctx = this.overlayCtx;
        const fullWidth = this.margin.left + this.chartWidth + this.margin.right;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, fullWidth, viewportHeight);

        const marginTop = this.margin.top;
        const marginLeft = this.margin.left;
        const yMin = scrollTop - marginTop - this.rowGap;
        const yMax = scrollTop - marginTop + viewportHeight + this.rowGap;

        // Ground truth overlay
        if (this.showGroundTruth && this.gtBySourceIP && xScale) {
            ctx.globalAlpha = 0.25;
            for (const ip of this.ipOrder) {
                const yPos = this.ipPositions?.get(ip);
                if (yPos === undefined || yPos < yMin || yPos > yMax) continue;
                const events = this.gtBySourceIP.get(ip);
                if (!events) continue;
                const screenY = yPos + marginTop - scrollTop;
                for (const evt of events) {
                    const x1 = xScale(evt.startTimeMicroseconds);
                    const x2 = xScale(evt.stopTimeMicroseconds || evt.startTimeMicroseconds);
                    const x = Math.min(x1, x2) + marginLeft;
                    const w = Math.max(3, Math.abs(x2 - x1));
                    ctx.fillStyle = this.eventColors[evt.eventType] || '#888';
                    ctx.fillRect(x, screenY - this.rowGap / 2, w, this.rowGap);
                }
            }
            ctx.globalAlpha = 1.0;
        }

        // Hover label
        if (this._hoveredIP && this.ipPositions) {
            const hoverY = this.ipPositions.get(this._hoveredIP);
            if (hoverY !== undefined && hoverY >= yMin && hoverY <= yMax) {
                const sy = hoverY + marginTop - scrollTop;
                ctx.font = '11px monospace';
                ctx.textBaseline = 'middle';
                const tw = ctx.measureText(this._hoveredIP).width;
                ctx.fillStyle = 'rgba(0,0,0,0.75)';
                ctx.fillRect(marginLeft - tw - 18, sy - 8, tw + 12, 16);
                ctx.fillStyle = '#fff';
                ctx.textAlign = 'right';
                ctx.fillText(this._hoveredIP, marginLeft - 12, sy);
                ctx.fillStyle = 'rgba(77,171,247,0.12)';
                ctx.fillRect(marginLeft, sy - this.rowGap / 2, this.chartWidth, this.rowGap);
            }
        }
    }

    enableHover(xScale, getScrollTop) {
        this.overlayCanvas.style.pointerEvents = 'auto';
        this._xScale = xScale;
        this._getScrollTop = getScrollTop;

        this.overlayCanvas.addEventListener('mousemove', (e) => {
            const rect = this.overlayCanvas.getBoundingClientRect();
            const mouseY = e.clientY - rect.top;
            const scrollTop = this._getScrollTop();
            const dataY = mouseY + scrollTop - this.margin.top;

            let closestIP = null;
            let closestDist = this.rowGap / 2;
            for (const ip of this.ipOrder) {
                const yPos = this.ipPositions?.get(ip);
                if (yPos === undefined) continue;
                const dist = Math.abs(yPos - dataY);
                if (dist < closestDist) {
                    closestDist = dist;
                    closestIP = ip;
                }
            }

            if (closestIP !== this._hoveredIP) {
                this._hoveredIP = closestIP;
                // Only overlay needs redraw — WebGL layer is unchanged
                this._drawOverlay(this._xScale, scrollTop, this.overlayCanvas.clientHeight, window.devicePixelRatio || 1);
            }
        });

        this.overlayCanvas.addEventListener('mouseleave', () => {
            if (this._hoveredIP) {
                this._hoveredIP = null;
                this._drawOverlay(this._xScale, this._getScrollTop(), this.overlayCanvas.clientHeight, window.devicePixelRatio || 1);
            }
        });
    }

    _getHeight(d) {
        if (!d.binned) return this.individualHeight;
        return this.hScale
            ? Math.max(this.minHeight, Math.min(this.maxHeight, this.hScale(d.count || 1)))
            : this.minHeight;
    }

    _getColorString(d) {
        if (!this.colorMap) return 'rgb(173,181,189)';
        const ct = d.closeType || d.invalidReason;
        if (this.colorMap instanceof Map) {
            return this.colorMap.get(ct) || this.colorMap.get(d.invalidReason) || 'rgb(173,181,189)';
        }
        return this.colorMap[ct] || 'rgb(173,181,189)';
    }

    hitTest(mouseX, mouseY, xScale, scrollTop) {
        const marginTop = this.margin.top;
        const marginLeft = this.margin.left;
        const dataY = mouseY + scrollTop - marginTop;
        const dataX = mouseX - marginLeft;

        for (const ip of this.ipOrder) {
            const yPos = this.ipPositions?.get(ip);
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
            break;
        }
        return null;
    }

    resize(chartWidth) {
        this.chartWidth = chartWidth;
    }

    destroy() {
        try { this.regl?.destroy(); } catch (e) {}
        if (this.canvas && this.canvas.parentElement) {
            this.canvas.parentElement.removeChild(this.canvas);
        }
        if (this.overlayCanvas && this.overlayCanvas.parentElement) {
            this.overlayCanvas.parentElement.removeChild(this.overlayCanvas);
        }
        this.regl = null;
    }
}

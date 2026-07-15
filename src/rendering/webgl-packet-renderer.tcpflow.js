// src/rendering/webgl-packet-renderer.tcpflow.js
// WebGL2 renderer for packet circles — used only by tcp-flow-analysis.js.
// Cloned/specialized from the SVG circle pipeline so other pages remain on SVG.
//
// Responsibilities:
//   * Draws colored circles (one per packet/bin) as point sprites.
//   * Maintains per-packet attribute buffers: x (data-space), y (px), radius, RGBA.
//   * Provides hit testing for hover/tooltip.
//   * Provides per-index opacity overrides for search dim/highlight.
//
// Coordinate system: data x (xScale input) and absolute pixel y (matches the
// y values produced by the existing layout pipeline, i.e. baseY + offsets).
// On render() we pass in the live xScale so we can convert to clip space and
// account for zoom transforms without re-uploading buffers.

const VERTEX_SHADER = `#version 300 es
precision highp float;
in float a_x;            // data-space x (microseconds-since-epoch domain)
in float a_y;            // pixel-space y (relative to mainGroup origin)
in float a_radius;       // pixel radius
in vec4  a_color;        // 0..1 rgba
in float a_opacity;      // 0..1 multiplier (search dim, hide)

uniform float u_xScale;  // pixels per data unit
uniform float u_xOffset; // data-space domain[0]
uniform float u_marginLeft;
uniform float u_marginTop;
uniform float u_scrollTop;
uniform vec2  u_viewport; // canvas CSS px (width, height)
uniform float u_dpr;
uniform float u_radiusBoost; // additive radius for highlight stroke pass

out vec4 v_color;
out float v_opacity;

void main() {
    // Convert data x to pixel x within mainGroup, then to canvas-local px.
    float px = (a_x - u_xOffset) * u_xScale + u_marginLeft;
    // Canvas Y origin is page top; mainGroup is offset by marginTop, then
    // shifted up by scroll position because the canvas is parented to the
    // scroll container and pinned at scrollTop.
    float py = a_y + u_marginTop - u_scrollTop;

    // Convert to clip space [-1, 1]; flip y (gl is y-up).
    vec2 clip = vec2(
        (px / u_viewport.x) * 2.0 - 1.0,
        1.0 - (py / u_viewport.y) * 2.0
    );
    gl_Position = vec4(clip, 0.0, 1.0);

    // gl_PointSize is in framebuffer pixels — multiply by DPR.
    float r = max(0.5, a_radius + u_radiusBoost);
    gl_PointSize = r * 2.0 * u_dpr;

    v_color = a_color;
    v_opacity = a_opacity;
}`;

const FRAGMENT_SHADER = `#version 300 es
precision highp float;
in vec4 v_color;
in float v_opacity;
out vec4 outColor;

uniform float u_strokeOnly; // 1.0 = draw ring (highlight pass), 0.0 = filled disk

void main() {
    vec2 d = gl_PointCoord - vec2(0.5);
    float dist = length(d) * 2.0; // 0 at center, 1 at edge
    if (dist > 1.0) discard;

    if (u_strokeOnly > 0.5) {
        // Draw a 2px-equivalent ring near the edge.
        if (dist < 0.78) discard;
        outColor = vec4(0.0, 0.0, 0.0, v_opacity);
    } else {
        // Soft anti-aliased edge in last ~6% of radius.
        float aa = smoothstep(1.0, 0.94, dist);
        outColor = vec4(v_color.rgb, v_color.a * v_opacity * aa);
    }
}`;

function compileShader(gl, type, source) {
    const sh = gl.createShader(type);
    gl.shaderSource(sh, source);
    gl.compileShader(sh);
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        const log = gl.getShaderInfoLog(sh);
        gl.deleteShader(sh);
        throw new Error('Shader compile failed: ' + log);
    }
    return sh;
}

function linkProgram(gl, vs, fs) {
    const p = gl.createProgram();
    gl.attachShader(p, vs);
    gl.attachShader(p, fs);
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
        const log = gl.getProgramInfoLog(p);
        gl.deleteProgram(p);
        throw new Error('Program link failed: ' + log);
    }
    return p;
}

function hexToRgb(hex) {
    if (!hex) return [0.5, 0.5, 0.5];
    let h = hex.replace('#', '');
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    return [
        parseInt(h.slice(0, 2), 16) / 255,
        parseInt(h.slice(2, 4), 16) / 255,
        parseInt(h.slice(4, 6), 16) / 255
    ];
}

export class WebGLPacketRenderer {
    /**
     * @param {HTMLElement} container - The scroll container (e.g. #chart-container).
     * @param {Object} margin - {top, right, bottom, left} for the SVG mainGroup.
     */
    constructor(container, margin) {
        this.container = container;
        this.margin = margin;
        this.canvas = document.createElement('canvas');
        const css = this.canvas.style;
        css.position = 'absolute';
        css.left = '0';
        css.top = '0';
        css.pointerEvents = 'none'; // SVG above (or peer) handles events
        css.zIndex = '0';
        if (getComputedStyle(container).position === 'static') {
            container.style.position = 'relative';
        }
        // Insert as the first child so the SVG (drawn after) sits on top for
        // hit testing of axis/labels/highlights.
        container.insertBefore(this.canvas, container.firstChild);

        const gl = this.canvas.getContext('webgl2', {
            antialias: false,
            alpha: true,
            premultipliedAlpha: true,
            preserveDrawingBuffer: false
        });
        if (!gl) throw new Error('WebGL2 not supported');
        this.gl = gl;

        const vs = compileShader(gl, gl.VERTEX_SHADER, VERTEX_SHADER);
        const fs = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT_SHADER);
        this.program = linkProgram(gl, vs, fs);
        gl.deleteShader(vs); gl.deleteShader(fs);

        this.attribs = {
            x: gl.getAttribLocation(this.program, 'a_x'),
            y: gl.getAttribLocation(this.program, 'a_y'),
            radius: gl.getAttribLocation(this.program, 'a_radius'),
            color: gl.getAttribLocation(this.program, 'a_color'),
            opacity: gl.getAttribLocation(this.program, 'a_opacity')
        };
        this.uniforms = {
            xScale: gl.getUniformLocation(this.program, 'u_xScale'),
            xOffset: gl.getUniformLocation(this.program, 'u_xOffset'),
            marginLeft: gl.getUniformLocation(this.program, 'u_marginLeft'),
            marginTop: gl.getUniformLocation(this.program, 'u_marginTop'),
            scrollTop: gl.getUniformLocation(this.program, 'u_scrollTop'),
            viewport: gl.getUniformLocation(this.program, 'u_viewport'),
            dpr: gl.getUniformLocation(this.program, 'u_dpr'),
            radiusBoost: gl.getUniformLocation(this.program, 'u_radiusBoost'),
            strokeOnly: gl.getUniformLocation(this.program, 'u_strokeOnly')
        };

        this.vao = gl.createVertexArray();
        this.buffers = {
            x: gl.createBuffer(),
            y: gl.createBuffer(),
            radius: gl.createBuffer(),
            color: gl.createBuffer(),
            opacity: gl.createBuffer()
        };
        this._bindVAO();

        // Per-packet CPU-side arrays (kept for hit testing, highlight updates)
        this.count = 0;
        this.xArr = null;        // Float32Array data x
        this.yArr = null;        // Float32Array pixel y
        this.rArr = null;        // Float32Array radius
        this.opArr = null;       // Float32Array opacity (per-instance)
        this.items = null;       // original processed[] (for hit-test payload)

        // Hit-test bucketing — bucket indices by pixel y row band.
        this.hitBucketY = new Map(); // bandY -> array of indices

        // Highlight (single hover) — rendered as second pass with stroke ring.
        this.hoverIndex = -1;

        // Width override: we expect to be sized to the SVG total width.
        this.totalWidth = 0;
    }

    _bindVAO() {
        const gl = this.gl;
        gl.bindVertexArray(this.vao);
        const setup = (buf, loc, size) => {
            gl.bindBuffer(gl.ARRAY_BUFFER, buf);
            gl.enableVertexAttribArray(loc);
            gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0);
        };
        setup(this.buffers.x, this.attribs.x, 1);
        setup(this.buffers.y, this.attribs.y, 1);
        setup(this.buffers.radius, this.attribs.radius, 1);
        setup(this.buffers.color, this.attribs.color, 4);
        setup(this.buffers.opacity, this.attribs.opacity, 1);
        gl.bindVertexArray(null);
    }

    /**
     * Upload packet data. `items` is the post-processed packet list with:
     *   { src_ip, dst_ip, ipPairKey, yPosWithOffset, binCenter|timestamp,
     *     binned, count, flagType (or flag_type) }
     */
    setData(items, opts) {
        const {
            rScale,
            RADIUS_MIN,
            flagColors,
            getFlagType
        } = opts;

        const n = items.length;
        // Reuse buffers across renders when capacity allows. Halves GC pressure
        // on heavy scroll where setData fires every frame.
        const cap = this._cap || 0;
        if (cap < n) {
            this._cap = Math.max(n, Math.ceil(n * 1.25));
            this.xArr = new Float32Array(this._cap);
            this.yArr = new Float32Array(this._cap);
            this.rArr = new Float32Array(this._cap);
            this._colArr = new Float32Array(this._cap * 4);
            this.opArr = new Float32Array(this._cap);
        }
        const xs = this.xArr;
        const ys = this.yArr;
        const rs = this.rArr;
        const cols = this._colArr;
        const ops = this.opArr;

        // Color cache: ~10 distinct flags, avoid hexToRgb on every packet.
        const colorCache = new Map();
        const lookupColor = (flag) => {
            let v = colorCache.get(flag);
            if (!v) {
                v = hexToRgb(flagColors[flag] || flagColors.OTHER || '#888');
                colorCache.set(flag, v);
            }
            return v;
        };

        const hitBuckets = new Map();
        const BAND = 24;

        for (let i = 0; i < n; i++) {
            const d = items[i];
            const x = d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp;
            const y = d.yPosWithOffset;
            const r = d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN;
            const flag = d.flagType || d.flag_type || (getFlagType ? getFlagType(d) : 'OTHER');
            const rgb = lookupColor(flag);

            xs[i] = Math.floor(x);
            ys[i] = y;
            rs[i] = r;
            const ci = i * 4;
            cols[ci] = rgb[0];
            cols[ci + 1] = rgb[1];
            cols[ci + 2] = rgb[2];
            cols[ci + 3] = 1;
            ops[i] = 1;

            const band = (y / BAND) | 0;
            const bucket = hitBuckets.get(band);
            if (bucket) bucket.push(i); else hitBuckets.set(band, [i]);
        }

        this.count = n;
        this.items = items;
        this.hitBucketY = hitBuckets;
        this.hitBand = BAND;
        this.hoverIndex = -1;

        const gl = this.gl;
        // Upload using subarray views so we don't ship trailing capacity bytes.
        const upload = (buf, data) => {
            gl.bindBuffer(gl.ARRAY_BUFFER, buf);
            gl.bufferData(gl.ARRAY_BUFFER, data, gl.DYNAMIC_DRAW);
        };
        upload(this.buffers.x, xs.subarray(0, n));
        upload(this.buffers.y, ys.subarray(0, n));
        upload(this.buffers.radius, rs.subarray(0, n));
        upload(this.buffers.color, cols.subarray(0, n * 4));
        upload(this.buffers.opacity, ops.subarray(0, n));
    }

    /**
     * Replace per-index opacity (e.g. dim non-matching packets during search).
     * @param {Float32Array|null} opArr - new opacity array, or null to reset to 1.
     */
    setOpacityArray(opArr) {
        if (!this.count) return;
        const gl = this.gl;
        if (!opArr) {
            this.opArr.fill(1);
        } else {
            this.opArr = opArr;
        }
        gl.bindBuffer(gl.ARRAY_BUFFER, this.buffers.opacity);
        gl.bufferData(gl.ARRAY_BUFFER, this.opArr, gl.DYNAMIC_DRAW);
    }

    /**
     * Set the data-space domain width for the chart (used to compute total
     * SVG width in CSS pixels, so we can size the canvas correctly).
     */
    setTotalWidth(totalWidth) {
        this.totalWidth = totalWidth;
    }

    /**
     * Resize the canvas to viewport and redraw. Called on every zoom/pan/scroll
     * frame — must be cheap.
     *
     * @param {Function} xScale - d3 scale (data → pixels within mainGroup)
     * @param {number} scrollTop - current container scrollTop
     * @param {number} viewportHeight - container clientHeight
     */
    render(xScale, scrollTop, viewportHeight) {
        const gl = this.gl;
        if (!this.count || !xScale) {
            this._resize(viewportHeight);
            this._clear();
            return;
        }

        const dpr = window.devicePixelRatio || 1;
        // Always derive total width from the live xScale + margins so window
        // resizes don't leave the canvas mis-sized.
        const xRange = xScale.range();
        const cssW = (this.margin.left + this.margin.right + (xRange[1] - xRange[0]));
        const cssH = viewportHeight;

        this._resize(cssH, cssW);

        // Pin canvas at scrollTop so we don't have to re-render on every scroll
        // beyond uniform updates.
        this.canvas.style.top = scrollTop + 'px';

        const domain = xScale.domain();
        const range = xScale.range();
        const pxPerUnit = (range[1] - range[0]) / (domain[1] - domain[0]);

        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.enable(gl.BLEND);
        gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

        gl.useProgram(this.program);
        gl.uniform1f(this.uniforms.xScale, pxPerUnit);
        gl.uniform1f(this.uniforms.xOffset, domain[0]);
        gl.uniform1f(this.uniforms.marginLeft, this.margin.left);
        gl.uniform1f(this.uniforms.marginTop, this.margin.top);
        gl.uniform1f(this.uniforms.scrollTop, scrollTop);
        gl.uniform2f(this.uniforms.viewport, cssW, cssH);
        gl.uniform1f(this.uniforms.dpr, dpr);
        gl.uniform1f(this.uniforms.radiusBoost, 0);
        gl.uniform1f(this.uniforms.strokeOnly, 0);

        gl.bindVertexArray(this.vao);
        gl.drawArrays(gl.POINTS, 0, this.count);

        // Hover stroke pass — draw a single ring around hovered point.
        if (this.hoverIndex >= 0 && this.hoverIndex < this.count) {
            // Single-point draw: use drawArrays with 1 vertex via offset trick.
            // Easier: just draw all and let stroke-only pass discard via opacity 0
            // for non-hovered. To avoid that, use a tiny dedicated buffer.
            this._drawHoverRing(pxPerUnit, domain[0], cssW, cssH, dpr, scrollTop);
        }

        gl.bindVertexArray(null);
    }

    _drawHoverRing(pxPerUnit, xOffset, cssW, cssH, dpr, scrollTop) {
        const gl = this.gl;
        const i = this.hoverIndex;
        if (!this._hoverVAO) {
            this._hoverVAO = gl.createVertexArray();
            this._hoverBuf = {
                x: gl.createBuffer(),
                y: gl.createBuffer(),
                radius: gl.createBuffer(),
                color: gl.createBuffer(),
                opacity: gl.createBuffer()
            };
            gl.bindVertexArray(this._hoverVAO);
            const setup = (buf, loc, size) => {
                gl.bindBuffer(gl.ARRAY_BUFFER, buf);
                gl.enableVertexAttribArray(loc);
                gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0);
            };
            setup(this._hoverBuf.x, this.attribs.x, 1);
            setup(this._hoverBuf.y, this.attribs.y, 1);
            setup(this._hoverBuf.radius, this.attribs.radius, 1);
            setup(this._hoverBuf.color, this.attribs.color, 4);
            setup(this._hoverBuf.opacity, this.attribs.opacity, 1);
            gl.bindVertexArray(null);
        }
        const upload = (buf, arr) => {
            gl.bindBuffer(gl.ARRAY_BUFFER, buf);
            gl.bufferData(gl.ARRAY_BUFFER, arr, gl.DYNAMIC_DRAW);
        };
        upload(this._hoverBuf.x, new Float32Array([this.xArr[i]]));
        upload(this._hoverBuf.y, new Float32Array([this.yArr[i]]));
        upload(this._hoverBuf.radius, new Float32Array([this.rArr[i]]));
        upload(this._hoverBuf.color, new Float32Array([0, 0, 0, 1]));
        upload(this._hoverBuf.opacity, new Float32Array([1]));

        gl.uniform1f(this.uniforms.radiusBoost, 1.5);
        gl.uniform1f(this.uniforms.strokeOnly, 1);
        gl.bindVertexArray(this._hoverVAO);
        gl.drawArrays(gl.POINTS, 0, 1);
        gl.uniform1f(this.uniforms.radiusBoost, 0);
        gl.uniform1f(this.uniforms.strokeOnly, 0);
    }

    _resize(viewportHeight, cssWidth) {
        const dpr = window.devicePixelRatio || 1;
        const w = cssWidth || this.totalWidth || this.container.clientWidth;
        const h = viewportHeight;
        const targetW = Math.round(w * dpr);
        const targetH = Math.round(h * dpr);
        if (this.canvas.width !== targetW || this.canvas.height !== targetH) {
            this.canvas.width = targetW;
            this.canvas.height = targetH;
            this.canvas.style.width = w + 'px';
            this.canvas.style.height = h + 'px';
        }
    }

    _clear() {
        const gl = this.gl;
        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);
    }

    /**
     * Find the topmost (smallest radius — drawn last) packet under (mx, my)
     * where the coordinates are in the SVG mainGroup space (i.e. data x in
     * pixels relative to mainGroup origin, py in absolute pixel y).
     *
     * @param {number} pxX - pixel x relative to mainGroup origin
     * @param {number} pxY - pixel y relative to mainGroup origin
     * @param {Function} xScale - to convert data x to pixels
     * @returns {{ index: number, datum: Object }|null}
     */
    hitTest(pxX, pxY, xScale) {
        if (!this.count) return null;
        // Inline xScale so we don't pay the d3-scale function call ~thousands
        // of times per mousemove; also lets us bail early via x-range checks.
        const domain = xScale.domain();
        const range = xScale.range();
        const xOff = domain[0];
        const xMul = (range[1] - range[0]) / (domain[1] - domain[0]);
        const xs = this.xArr;
        const ys = this.yArr;
        const rs = this.rArr;
        const band = (pxY / this.hitBand) | 0;
        let best = -1;
        let bestR = Infinity;
        for (let b = band - 1; b <= band + 1; b++) {
            const list = this.hitBucketY.get(b);
            if (!list) continue;
            for (let k = 0; k < list.length; k++) {
                const i = list[k];
                const r = rs[i];
                if (r >= bestR) continue; // smaller circles only (drawn on top)
                const dy = ys[i] - pxY;
                if (dy < -r || dy > r) continue;
                const dx = (xs[i] - xOff) * xMul - pxX;
                if (dx < -r || dx > r) continue;
                if (dx * dx + dy * dy <= r * r) {
                    best = i;
                    bestR = r;
                }
            }
        }
        if (best < 0) return null;
        return { index: best, datum: this.items[best] };
    }

    setHover(index) {
        this.hoverIndex = (index == null) ? -1 : index;
    }

    /** Update margin (e.g. on resize / re-init). */
    setMargin(margin) {
        this.margin = margin;
    }

    /** Hide all canvas content (e.g. when leaving packet view). */
    hide() {
        this.canvas.style.display = 'none';
    }

    show() {
        this.canvas.style.display = '';
    }

    /** Free GPU resources. Call when re-creating the visualization. */
    destroy() {
        const gl = this.gl;
        try {
            for (const buf of Object.values(this.buffers)) gl.deleteBuffer(buf);
            if (this._hoverBuf) for (const buf of Object.values(this._hoverBuf)) gl.deleteBuffer(buf);
            gl.deleteVertexArray(this.vao);
            if (this._hoverVAO) gl.deleteVertexArray(this._hoverVAO);
            gl.deleteProgram(this.program);
            // Browsers cap WebGL context count (~16). Force-release so churn
            // through visualizeTimeArcs doesn't exhaust the pool.
            const ext = gl.getExtension('WEBGL_lose_context');
            if (ext) ext.loseContext();
        } catch {}
        if (this.canvas.parentNode) this.canvas.parentNode.removeChild(this.canvas);
    }
}

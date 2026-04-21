// src/rendering/webgl-lozenges.js
// WebGL instanced renderer for flow lozenges — replaces SVG <rect> elements
// for performance with 10K+ IP rows.

const VERT_SRC = `#version 300 es
precision highp float;

// Per-vertex: unit quad corner
in vec2 a_corner;       // (0,0) (1,0) (0,1)  (1,0) (1,1) (0,1)

// Per-instance
in float a_xUs;         // bin start in microseconds (data space)
in float a_wUs;         // bin width in microseconds
in float a_yPx;         // y center in pixels
in float a_hPx;         // height in pixels
in vec3  a_color;       // RGB 0-1
in float a_radius;      // corner radius (= height/2)

// Uniforms for xScale transform: pixelX = xUs * u_xScale + u_xOffset
uniform float u_xScale;
uniform float u_xOffset;
uniform float u_scrollTop;     // container scroll offset
uniform vec2  u_viewport;      // canvas size in pixels
uniform float u_minWidth;      // minimum lozenge width in pixels

out vec2  v_uv;         // local UV within the rect [0,1]
out vec2  v_size;       // rect size in pixels
out float v_radius;
out vec3  v_color;

void main() {
    // Transform x from microseconds to pixels
    float xPx = a_xUs * u_xScale + u_xOffset;
    float wPx = max(u_minWidth, a_wUs * u_xScale);

    // Y in canvas space (scroll-adjusted)
    float yPx = a_yPx - u_scrollTop;

    // Quad corner position in pixels
    float left = xPx;
    float top  = yPx - a_hPx * 0.5;
    vec2 posPx = vec2(left, top) + a_corner * vec2(wPx, a_hPx);

    // To clip space
    gl_Position = vec4(
        posPx.x / u_viewport.x * 2.0 - 1.0,
        1.0 - posPx.y / u_viewport.y * 2.0,
        0.0, 1.0
    );

    v_uv     = a_corner;
    v_size   = vec2(wPx, a_hPx);
    v_radius = a_radius;
    v_color  = a_color;
}
`;

const FRAG_SRC = `#version 300 es
precision highp float;

in vec2  v_uv;
in vec2  v_size;
in float v_radius;
in vec3  v_color;

out vec4 fragColor;

void main() {
    // Position within the rect in pixels (origin at center)
    vec2 p = (v_uv - 0.5) * v_size;
    // Half-size minus radius
    vec2 b = v_size * 0.5 - vec2(v_radius);
    // Signed distance to rounded rect
    vec2 d = abs(p) - b;
    float dist = length(max(d, 0.0)) + min(max(d.x, d.y), 0.0) - v_radius;
    // Anti-alias
    float alpha = 1.0 - smoothstep(-0.5, 0.5, dist);
    if (alpha < 0.01) discard;
    fragColor = vec4(v_color, alpha);
}
`;

function compileShader(gl, type, src) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        console.error('Shader compile error:', gl.getShaderInfoLog(s));
        gl.deleteShader(s);
        return null;
    }
    return s;
}

function hexToRGB(hex) {
    if (!hex || hex.length < 4) return [0.68, 0.71, 0.74]; // #adb5bd fallback
    hex = hex.replace('#', '');
    if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
    return [
        parseInt(hex.slice(0,2), 16) / 255,
        parseInt(hex.slice(2,4), 16) / 255,
        parseInt(hex.slice(4,6), 16) / 255
    ];
}

export class WebGLLozengeRenderer {
    constructor(chartEl, margin, chartWidth) {
        this.chartEl = chartEl;
        this.margin = margin;
        this.chartWidth = chartWidth;
        this.items = [];       // original data items (for hit testing)
        this.yStarts = [];     // sorted y values for binary search
        this.instanceCount = 0;

        // Create canvas — absolute-positioned in the scroll container.
        // Top is updated on scroll to keep it in the visible viewport.
        this.canvas = document.createElement('canvas');
        this.canvas.style.position = 'absolute';
        this.canvas.style.left = margin.left + 'px';
        this.canvas.style.top = margin.top + 'px';
        this.canvas.style.pointerEvents = 'none';
        this.canvas.style.zIndex = '1';

        this.container = chartEl.closest('#chart-container') || chartEl.parentElement;
        this.container.style.position = 'relative';
        this.container.appendChild(this.canvas);

        // Init GL
        this.gl = this.canvas.getContext('webgl2', { alpha: true, premultipliedAlpha: false, antialias: false });
        if (!this.gl) throw new Error('WebGL2 not available');

        this._initGL();
    }

    _initGL() {
        const gl = this.gl;
        gl.enable(gl.BLEND);
        gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

        // Compile program
        const vs = compileShader(gl, gl.VERTEX_SHADER, VERT_SRC);
        const fs = compileShader(gl, gl.FRAGMENT_SHADER, FRAG_SRC);
        this.program = gl.createProgram();
        gl.attachShader(this.program, vs);
        gl.attachShader(this.program, fs);
        gl.linkProgram(this.program);
        if (!gl.getProgramParameter(this.program, gl.LINK_STATUS)) {
            console.error('Program link error:', gl.getProgramInfoLog(this.program));
            return;
        }
        gl.useProgram(this.program);

        // Attribute locations
        this.loc = {
            corner: gl.getAttribLocation(this.program, 'a_corner'),
            xUs:    gl.getAttribLocation(this.program, 'a_xUs'),
            wUs:    gl.getAttribLocation(this.program, 'a_wUs'),
            yPx:    gl.getAttribLocation(this.program, 'a_yPx'),
            hPx:    gl.getAttribLocation(this.program, 'a_hPx'),
            color:  gl.getAttribLocation(this.program, 'a_color'),
            radius: gl.getAttribLocation(this.program, 'a_radius'),
        };

        // Uniform locations
        this.uni = {
            xScale:    gl.getUniformLocation(this.program, 'u_xScale'),
            xOffset:   gl.getUniformLocation(this.program, 'u_xOffset'),
            scrollTop: gl.getUniformLocation(this.program, 'u_scrollTop'),
            viewport:  gl.getUniformLocation(this.program, 'u_viewport'),
            minWidth:  gl.getUniformLocation(this.program, 'u_minWidth'),
        };

        // Quad vertices (two triangles)
        const quadVerts = new Float32Array([
            0,0, 1,0, 0,1,
            1,0, 1,1, 0,1
        ]);
        this.quadBuf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, this.quadBuf);
        gl.bufferData(gl.ARRAY_BUFFER, quadVerts, gl.STATIC_DRAW);

        // Instance buffer (created in setData)
        this.instanceBuf = gl.createBuffer();

        // VAO
        this.vao = gl.createVertexArray();
        gl.bindVertexArray(this.vao);

        // Quad corner attribute (per vertex)
        gl.bindBuffer(gl.ARRAY_BUFFER, this.quadBuf);
        gl.enableVertexAttribArray(this.loc.corner);
        gl.vertexAttribPointer(this.loc.corner, 2, gl.FLOAT, false, 0, 0);

        // Instance attributes will be set up in setData
        gl.bindVertexArray(null);
    }

    /**
     * Pack lozenge items into GPU buffer.
     * @param {Array} items - processed flow bin items with yPosWithOffset set
     * @param {Function|Map} colorMap - closeType → hex color
     * @param {Function} hScale - count → height scale (d3.scaleSqrt)
     * @param {number} minHeight - minimum lozenge height
     * @param {number} maxHeight - maximum lozenge max height
     */
    setData(items, colorMap, hScale, { minHeight = 4, maxHeight = 20 } = {}) {
        const gl = this.gl;
        if (!gl) return;

        // Resolve color function
        const getColor = (d) => {
            if (!colorMap) return '#adb5bd';
            if (typeof colorMap === 'function') return colorMap(d.closeType, d.invalidReason);
            if (colorMap instanceof Map) return colorMap.get(d.closeType) || colorMap.get(d.invalidReason) || '#adb5bd';
            return colorMap[d.closeType] || '#adb5bd';
        };

        const getH = (d) => {
            return hScale ? Math.max(minHeight, Math.min(maxHeight, hScale(d.count || 1))) : minHeight;
        };

        // Sort by Y for viewport culling
        const sorted = items.slice().sort((a, b) => (a.yPosWithOffset || a.yPos || 0) - (b.yPosWithOffset || b.yPos || 0));
        this.items = sorted;
        this.instanceCount = sorted.length;

        // Build float32 array: 8 floats per instance
        // [xUs, wUs, yPx, hPx, r, g, b, radius]
        const FLOATS_PER = 8;
        const buf = new Float32Array(sorted.length * FLOATS_PER);
        this.yStarts = new Float32Array(sorted.length);

        for (let i = 0; i < sorted.length; i++) {
            const d = sorted[i];
            const xUs = d.binStart ?? d.startTime ?? d.binCenter ?? 0;
            const endUs = d.binEnd ?? d.endTime ?? xUs;
            const wUs = endUs - xUs;
            const yPx = d.yPosWithOffset ?? d.yPos ?? 0;
            const hPx = getH(d);
            const [r, g, b] = hexToRGB(getColor(d));
            const radius = hPx / 2;

            const off = i * FLOATS_PER;
            buf[off + 0] = xUs;
            buf[off + 1] = wUs;
            buf[off + 2] = yPx;
            buf[off + 3] = hPx;
            buf[off + 4] = r;
            buf[off + 5] = g;
            buf[off + 6] = b;
            buf[off + 7] = radius;

            this.yStarts[i] = yPx - hPx / 2;
        }

        // Upload to GPU
        gl.bindVertexArray(this.vao);
        gl.bindBuffer(gl.ARRAY_BUFFER, this.instanceBuf);
        gl.bufferData(gl.ARRAY_BUFFER, buf, gl.STATIC_DRAW);

        const stride = FLOATS_PER * 4;
        const setupAttr = (loc, size, offset) => {
            if (loc < 0) return;
            gl.enableVertexAttribArray(loc);
            gl.vertexAttribPointer(loc, size, gl.FLOAT, false, stride, offset * 4);
            gl.vertexAttribDivisor(loc, 1);
        };

        setupAttr(this.loc.xUs,    1, 0);
        setupAttr(this.loc.wUs,    1, 1);
        setupAttr(this.loc.yPx,    1, 2);
        setupAttr(this.loc.hPx,    1, 3);
        setupAttr(this.loc.color,  3, 4);
        setupAttr(this.loc.radius, 1, 7);

        gl.bindVertexArray(null);
    }

    /**
     * Render visible lozenges.
     * @param {Function} xScale - D3 linear scale (domain in µs, range in px)
     * @param {number} scrollTop - container scroll offset
     * @param {number} viewportHeight - visible height in px
     */
    render(xScale, scrollTop, viewportHeight) {
        const gl = this.gl;
        if (!gl || this.instanceCount === 0) return;

        const dpr = window.devicePixelRatio || 1;
        const cw = this.chartWidth;
        const ch = viewportHeight;

        // Resize canvas if needed
        if (this.canvas.width !== Math.round(cw * dpr) || this.canvas.height !== Math.round(ch * dpr)) {
            this.canvas.width = Math.round(cw * dpr);
            this.canvas.height = Math.round(ch * dpr);
            this.canvas.style.width = cw + 'px';
            this.canvas.style.height = ch + 'px';
        }

        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);

        // Compute xScale uniforms: pixelX = xUs * scale + offset
        const domain = xScale.domain();
        const range = xScale.range();
        const xScaleFactor = (range[1] - range[0]) / (domain[1] - domain[0]);
        const xOffsetVal = range[0] - domain[0] * xScaleFactor;

        gl.useProgram(this.program);
        gl.uniform1f(this.uni.xScale, xScaleFactor);
        gl.uniform1f(this.uni.xOffset, xOffsetVal);
        gl.uniform1f(this.uni.scrollTop, scrollTop);
        gl.uniform2f(this.uni.viewport, cw, ch);
        gl.uniform1f(this.uni.minWidth, 4.0); // LOZENGE_MIN_WIDTH

        // Viewport culling: find visible Y range
        const yMin = scrollTop - this.margin.top - 40; // padding
        const yMax = yMin + viewportHeight + 80;

        let firstIdx = this._binarySearch(yMin);
        let lastIdx = this._binarySearch(yMax);
        if (lastIdx < this.instanceCount) lastIdx++;

        const visibleCount = lastIdx - firstIdx;
        if (visibleCount <= 0) return;

        // Draw all instances — GPU clips off-screen ones via vertex shader.
        // With typical viewports showing ~30 rows out of 17K, most fragments
        // are discarded cheaply by viewport clipping.
        gl.bindVertexArray(this.vao);
        gl.drawArraysInstanced(gl.TRIANGLES, 0, 6, this.instanceCount);
        gl.bindVertexArray(null);
    }

    /**
     * Binary search for the first instance with yStart >= target.
     */
    _binarySearch(targetY) {
        let lo = 0, hi = this.yStarts.length;
        while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (this.yStarts[mid] < targetY) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    /**
     * Hit test: find the item under (mouseX, mouseY) in chart coordinates.
     * @param {number} mx - mouse X in chart content area (after margin.left subtracted)
     * @param {number} my - mouse Y in chart content area (after margin.top subtracted, scroll-adjusted)
     * @param {Function} xScale - current D3 xScale
     * @returns {Object|null} the data item, or null
     */
    hitTest(mx, my, xScale) {
        // my is already in data-space Y (scroll-adjusted, margin-adjusted)
        for (let i = 0; i < this.items.length; i++) {
            const d = this.items[i];
            const yPx = d.yPosWithOffset ?? d.yPos ?? 0;
            const hPx = d._renderedHeight || 8;
            if (my < yPx - hPx / 2 || my > yPx + hPx / 2) continue;

            const xStart = d.binStart ?? d.startTime ?? d.binCenter ?? 0;
            const xEnd = d.binEnd ?? d.endTime ?? xStart;
            const xPxStart = xScale(xStart);
            const xPxEnd = Math.max(xPxStart + 4, xScale(xEnd));
            if (mx >= xPxStart && mx <= xPxEnd) return d;
        }
        return null;
    }

    resize(chartWidth, viewportHeight) {
        this.chartWidth = chartWidth;
        // Canvas will be resized on next render()
    }

    destroy() {
        if (this.gl) {
            this.gl.deleteBuffer(this.quadBuf);
            this.gl.deleteBuffer(this.instanceBuf);
            this.gl.deleteVertexArray(this.vao);
            this.gl.deleteProgram(this.program);
        }
        if (this.canvas && this.canvas.parentElement) {
            this.canvas.parentElement.removeChild(this.canvas);
        }
        this.gl = null;
    }
}

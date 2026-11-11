/**
 * @file mmr_canvas_renderer.js
 * @module client/ui/mmr_canvas_renderer.js - Merkle Mountain Range (MMR) 2D/3D Topography Canvas Renderer
 *
 * @brief Interactive hardware-accelerated 2D and 3D visualization engine rendering
 *        Merkle Mountain Range (MMR) state accumulators, peak aggregations, and
 *        asynchronous cryptographic proof verification paths.
 *
 * @details
 * Architectural Responsibilities:
 * 1. Multi-Dimensional Projection Pipeline:
 *    - 2D Hierarchical Tree: Renders binary mountain topography with dynamic node sizing,
 *      proportional leaf spacing, and theme-adaptive coloring.
 *    - 3D WebGL Projection: Projects tree coordinates into a 3D perspective space with
 *      user-driven yaw/pitch rotation, depth sorting, and particle-based point shaders.
 * 2. Animated Proof Traversal:
 *    Renders progressive animations highlighting Merkle inclusion paths from leaf nodes
 *    upward through parent peaks upon transaction match detection.
 * 3. Inspection Magnifier (Loupe):
 *    Provides an interactive circular magnification lens for probing high-density MMR nodes.
 * 4. Cooperative Resource Throttling:
 *    Listens to browser visibility events (`document.hidden`), pausing rendering loops when
 *    the tab is backgrounded to respect client CPU and battery budgets.
 *
 * @invariants
 * - Coordinate Consistency: `_calculateCoordinates` recalculates positions strictly within
 *   canvas physical dimensions `[paddingX, width - paddingX]`.
 * - WebGL Context Sanitation: Toggling between 2D and 3D cleanly deletes shader programs
 *   and vertex buffers to prevent WebGL memory leaks.
 * - Non-Negative Radius: Dynamic node radius is strictly bounded: `2.5 <= radius <= nodeRadius`.
 *
 * @standards
 * - W3C HTML5 Canvas 2D Context.
 * - Khronos WebGL 1.0 Specification.
 * - Peter Todd: Merkle Mountain Range Topography Specification.
 *
 * @dependencies
 * - Standard DOM Canvas (`HTMLCanvasElement`, `CanvasRenderingContext2D`, `WebGLRenderingContext`).
 *
 * @threading
 * - Executes in the browser main UI animation frame thread (`requestAnimationFrame`).
 * - Event-driven mouse, touch, and visibility listeners.
 */

/* ============================================================================
 * SECTION 1: CANVAS RENDERER CONSTRUCTOR & LIFECYCLE
 * ============================================================================ */

/**
 * @class MmrCanvasRenderer
 * @brief Hardware-accelerated renderer displaying dynamic MMR trees and proof animations.
 */
class MmrCanvasRenderer {
    /**
     * @brief Instantiates the MMR canvas renderer.
     * @param {HTMLCanvasElement} canvas Target HTML5 canvas element to bind.
     */
    constructor(canvas) {
        /** @type {HTMLCanvasElement} Bound canvas element. */
        this.canvas = canvas;
        /** @type {CanvasRenderingContext2D|null} 2D rendering context. */
        this.ctx = canvas.getContext('2d');
        /** @type {WebGLRenderingContext|null} WebGL 3D context (initialized lazily). */
        this.gl = null;
        /** @type {Array<Object>} Linear node array `{ hash, position, height, parent, leftChild, rightChild }`. */
        this.nodes = [];
        /** @type {Map<number, Object>} O(1) index map resolving node position to node object. */
        this.nodesMap = new Map();
        /** @type {Map<number, {x: number, y: number}>} Calculated screen coordinates. */
        this.positions = new Map();
        /** @type {Set<number>} Set of node positions currently highlighted. */
        this.highlightedNodes = new Set();
        /** @type {Array<Object>} Active animated proof path edges. */
        this.activePathEdges = [];

        this.nodeRadius = 10;
        this.rowHeight = 50;
        this.leafSpacing = 48;
        this.paddingX = 40;
        this.paddingY = 40;

        this.width = canvas.width;
        this.height = canvas.height;

        // 3D perspective projection variables
        this.is3D = false;
        this.angleX = -0.3;
        this.angleY = 0.4;
        this.zoom = 1.0;
        this.isDragging = false;
        this.wasDragging = false;
        this.lastMouseX = 0;
        this.lastMouseY = 0;
        this.velocityX = 0;
        this.velocityY = 0;

        this.animationFrameId = null;
        this.nodeScales = new Map();
        this.isTabVisible = true;
        this.isLoupeActive = false;
        this.lastClientX = null;
        this.lastClientY = null;

        // Register renderer instance globally for theme-switched updates
        if (!window.mmrRenderers) window.mmrRenderers = [];
        window.mmrRenderers.push(this);

        this._createLoupeElement();
        this._initMouseEvents();
        this._initVisibilityListener();
        this._initResizeObserver();
    }

    /* ============================================================================
     * SECTION 2: VIEWPORT RESIZING, THEMES & 2D/3D MODE TOGGLING
     * ============================================================================ */

    /**
     * @brief Observes container resize and device orientation changes to maintain MMR layout integrity.
     * @return {void}
     */
    _initResizeObserver() {
        if (window.ResizeObserver && this.canvas && this.canvas.parentElement) {
            this.resizeObserver = new ResizeObserver(() => {
                this.handleResize();
            });
            this.resizeObserver.observe(this.canvas.parentElement);
        }

        // Multi-phase polling synchronizes with iOS Safari's ~300ms rotation animation
        this.orientationHandler = () => {
            this.handleResize();
            setTimeout(() => this.handleResize(), 100);
            setTimeout(() => this.handleResize(), 300);
            setTimeout(() => this.handleResize(), 500);
        };

        window.addEventListener('orientationchange', this.orientationHandler);
        window.addEventListener('resize', this.orientationHandler);
    }

    /**
     * @brief Recalculates canvas pixel backing store and re-centers all node coordinates.
     * @return {void}
     */
    handleResize() {
        const parent = this.canvas ? this.canvas.parentElement : null;
        if (!parent || parent.clientWidth <= 0 || parent.clientHeight <= 0) return;

        const newWidth = Math.floor(parent.clientWidth);
        const newHeight = Math.floor(parent.clientHeight);

        if (newWidth !== this.width || newHeight !== this.height) {
            this.width = newWidth;
            this.height = newHeight;
            this._calculateCoordinates();
        }

        this.draw();
    }

    /**
     * @brief Binds visibility change listener to pause animation loops when tab is hidden.
     * @return {void}
     */
    _initVisibilityListener() {
        this.visibilityHandler = () => {
            this.isTabVisible = !document.hidden;
            if (this.isTabVisible) {
                if (this.is3D) {
                    this._start3DLoop();
                } else {
                    this._startAnimationLoop();
                }
            } else {
                if (this.animationFrameId) {
                    cancelAnimationFrame(this.animationFrameId);
                    this.animationFrameId = null;
                }
            }
        };
        document.addEventListener('visibilitychange', this.visibilityHandler);
    }

    /**
     * @brief Toggles rendering pipeline between Canvas2D and WebGL 3D mode.
     *
     * @details
     * Tears down existing shaders and buffers to prevent GPU memory leaks, clones the
     * canvas element to reset browser context locks, rebinds mouse/touch listeners,
     * and restarts the appropriate animation frame loop.
     *
     * @return {void}
     * @complexity Time: O(1), Space: O(1).
     */
    toggleMode() {
        this.is3D = !this.is3D;

        // Cancel any active animation loops first
        if (this.animationFrameId) {
            cancelAnimationFrame(this.animationFrameId);
            this.animationFrameId = null;
        }

        // Enforce strict performance budgets by preventing WebGL memory leaks on context destruction
        if (!this.is3D && this.gl) {
            const gl = this.gl;
            if (this.pointBuffer) gl.deleteBuffer(this.pointBuffer);
            if (this.lineBuffer) gl.deleteBuffer(this.lineBuffer);
            if (this.pointProgram) gl.deleteProgram(this.pointProgram);
            if (this.lineProgram) gl.deleteProgram(this.lineProgram);
            
            this.gl = null;
        }

        // Recreate and replace the canvas element in the DOM to reset its rendering context mapping
        const oldCanvas = this.canvas;
        const newCanvas = oldCanvas.cloneNode(true);

        // Reset the cloned canvas attributes back to their original logical dimensions
        // to prevent cumulative high-DPI scaling expansion on successive toggles
        newCanvas.width = this.width;
        newCanvas.height = this.height;

        oldCanvas.parentNode.replaceChild(newCanvas, oldCanvas);

        this.canvas = newCanvas;

        if (this.is3D) {
            this.ctx = null;
            this.gl = this.canvas.getContext('webgl', { alpha: false, antialias: true, preserveDrawingBuffer: true }) || this.canvas.getContext('experimental-webgl', { alpha: false, antialias: true, preserveDrawingBuffer: true });
            if (this.gl) {
                this._initWebGL();
            }
            if (!this.gl) {
                console.warn('[WebGL] Initialization failed, falling back to 2D Canvas.');
                this.is3D = false;
            }
        }

        if (!this.is3D) {
            this.gl = null;
            this.ctx = this.canvas.getContext('2d');
            if (this.isTabVisible) {
                this._startAnimationLoop(); // Restart the 2D loop to resume active path or node-entry scaling animations
            }
        } else {
            if (this.isTabVisible) {
                this._start3DLoop();
            }
        }

        this._createLoupeElement();
        this._initMouseEvents();
        this.draw();
    }

    /**
      * @brief Resizes canvas internal backing store to match parent container and high-DPI scaling.
      * @return {void}
      */
     _resizeCanvas() {
        const parent = this.canvas.parentElement;
        if (parent && parent.clientWidth > 0 && parent.clientHeight > 0) {
            const newWidth = Math.floor(parent.clientWidth);
            const newHeight = Math.floor(parent.clientHeight);

            if (newWidth !== this.width || newHeight !== this.height) {
                this.width = newWidth;
                this.height = newHeight;
                this._calculateCoordinates();
            }
        }

        const dpr = window.devicePixelRatio || 1;
        const targetWidth = this.width * dpr;
        const targetHeight = this.height * dpr;

        // Only scale and reset the backing store if the physical size or device-pixel-ratio actually changes.
        if (this.canvas.width !== targetWidth || this.canvas.height !== targetHeight) {
            this.canvas.width = targetWidth;
            this.canvas.height = targetHeight;

            if (this.ctx && !this.is3D) {
                this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // Apply non-cumulative DPI scaling transform
            }
        }
    }

    /* ============================================================================
      * SECTION 3: WEBGL 3D SHADER PIPELINE & RENDERING KERNEL
      * ============================================================================ */

     /**
      * @brief Compiles point and line GLSL shaders and initializes WebGL state.
      * @return {void}
      * @complexity Time: O(1) shader compilation, Space: O(1) GPU buffer allocation.
      */
     _initWebGL() {
        const gl = this.gl;
        if (!gl) return;

        try {
            function createShader(gl, type, source) {
                const shader = gl.createShader(type);
                gl.shaderSource(shader, source);
                gl.compileShader(shader);
                if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
                    console.error('[WebGL] Shader compile error:', gl.getShaderInfoLog(shader));
                    gl.deleteShader(shader);
                    return null;
                }
                return shader;
            }

            function createProgram(gl, vsSource, fsSource) {
                const vs = createShader(gl, gl.VERTEX_SHADER, vsSource);
                const fs = createShader(gl, gl.FRAGMENT_SHADER, fsSource);
                if (!vs || !fs) return null;
                const program = gl.createProgram();
                gl.attachShader(program, vs);
                gl.attachShader(program, fs);
                gl.linkProgram(program);
                if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
                    console.error('[WebGL] Program linking error:', gl.getProgramInfoLog(program));
                    return null;
                }
                return program;
            }

            const vsPointSource = `
                attribute vec3 a_position;
                attribute vec4 a_color;
                attribute float a_size;
                varying vec4 v_color;
                void main() {
                    gl_Position = vec4(a_position, 1.0);
                    gl_PointSize = a_size;
                    v_color = a_color;
                }
            `;
            const fsPointSource = `
                precision mediump float;
                varying vec4 v_color;
                void main() {
                    vec2 circCoord = gl_PointCoord - vec2(0.5, 0.5);
                    float distSq = dot(circCoord, circCoord);
                    if (distSq > 0.25) {
                        discard;
                    }
                    float intensity = 1.0 - (distSq * 4.0);
                    intensity = clamp(intensity, 0.0, 1.0);
                    float edgeAlpha = smoothstep(0.25, 0.21, distSq);
                    vec3 finalColor = v_color.rgb + vec3(0.15, 0.15, 0.15) * intensity;
                    gl_FragColor = vec4(finalColor, v_color.a * edgeAlpha);
                }
            `;

            const vsLineSource = `
                attribute vec3 a_position;
                attribute vec4 a_color;
                varying vec4 v_color;
                void main() {
                    gl_Position = vec4(a_position, 1.0);
                    v_color = a_color;
                }
            `;
            const fsLineSource = `
                precision mediump float;
                varying vec4 v_color;
                void main() {
                    gl_FragColor = v_color;
                }
            `;

            this.pointProgram = createProgram(gl, vsPointSource, fsPointSource);
            this.lineProgram = createProgram(gl, vsLineSource, fsLineSource);

            if (this.pointProgram && this.lineProgram) {
                this.pointBuffer = gl.createBuffer();
                this.lineBuffer = gl.createBuffer();
            } else {
                this.gl = null;
            }
        } catch (e) {
            console.error('[WebGL] Failed to initialize WebGL pipeline:', e);
            this.gl = null;
        }
    }

    /**
     * @brief Renders the MMR tree in 3D perspective space using compiled WebGL shaders.
     * @return {void}
     * @complexity Time: O(nodes.length), Space: O(nodes.length * sizeof(vertex)).
     */
    _drawWebGL() {
        const gl = this.gl;
        if (!gl || !this.pointProgram || !this.lineProgram) return;

        gl.viewport(0, 0, this.canvas.width, this.canvas.height);
        const isOrange = document.documentElement.classList.contains('orange-mode');
        const isLight = document.documentElement.classList.contains('light-mode');
        if (isOrange) {
            if (isLight) {
                gl.clearColor(0.9922, 0.9843, 0.9686, 1.0); // #fdfbf7
            } else {
                gl.clearColor(0.0706, 0.0588, 0.0431, 1.0); // #120f0b
            }
        } else {
            if (isLight) {
                gl.clearColor(0.9725, 0.9804, 0.9882, 1.0); // #f8fafc
            } else {
                gl.clearColor(0.0588, 0.0902, 0.1647, 1.0); // #0f172a
            }
        }
        gl.enable(gl.DEPTH_TEST);
        gl.depthFunc(gl.LEQUAL);
        gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

        gl.enable(gl.BLEND);
        gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

        const lineVertices = [];
        const addLine = (posA, posB, r, g, b, a) => {
            const pA = this._getProjectedPosition(posA);
            const pB = this._getProjectedPosition(posB);
            if (pA && pB) {
                const xa = (pA.x / this.width) * 2 - 1;
                const ya = (1 - pA.y / this.height) * 2 - 1;
                const xb = (pB.x / this.width) * 2 - 1;
                const yb = (1 - pB.y / this.height) * 2 - 1;
                
                // Scale Z coordinates consistently to prevent perspective depth clipping under high rotation angles
                const za = pA.z / 1000.0;
                const zb = pB.z / 1000.0;
                
                lineVertices.push(xa, ya, za, r, g, b, a);
                lineVertices.push(xb, yb, zb, r, g, b, a);
            }
        };

        // Standard Connection Lines
        this.nodes.forEach(node => {
            if (node.parent !== -1) {
                if (isOrange) {
                    if (isLight) addLine(node.position, node.parent, 0.9059, 0.8980, 0.8941, 1.0); // #e7e5e4
                    else addLine(node.position, node.parent, 0.2039, 0.1647, 0.1294, 1.0); // #342a21
                } else {
                    if (isLight) addLine(node.position, node.parent, 0.7961, 0.8353, 0.8824, 1.0); // #cbd5e1
                    else addLine(node.position, node.parent, 0.2784, 0.3333, 0.4118, 1.0); // #475569
                }
            }
        });

        // Animated Proof Paths
        this.activePathEdges.forEach(edge => {
            const start = this._getProjectedPosition(edge.from);
            const end = this._getProjectedPosition(edge.to);
            if (start && end) {
                const curX = start.x + (end.x - start.x) * edge.progress;
                const curY = start.y + (end.y - start.y) * edge.progress;
                const curZ = start.z + (end.z - start.z) * edge.progress;

                const xa = (start.x / this.width) * 2 - 1;
                const ya = (1 - start.y / this.height) * 2 - 1;
                const xb = (curX / this.width) * 2 - 1;
                const yb = (1 - curY / this.height) * 2 - 1;

                const za = start.z / 1000.0;
                const zcur = curZ / 1000.0;

                let r_path = isLight ? 0.02 : 0.0627;
                let g_path = isLight ? 0.59 : 0.7255;
                let b_path = isLight ? 0.41 : 0.5059;
                
                if (isOrange) {
                    r_path = isLight ? 0.9176 : 0.9686; // #ea580c / #f7931a
                    g_path = isLight ? 0.3451 : 0.5765;
                    b_path = isLight ? 0.0471 : 0.1020;
                }

                lineVertices.push(xa, ya, za, r_path, g_path, b_path, 1.0);
                lineVertices.push(xb, yb, zcur, r_path, g_path, b_path, 1.0);
            }
        });

        if (lineVertices.length > 0) {
            gl.useProgram(this.lineProgram);
            gl.bindBuffer(gl.ARRAY_BUFFER, this.lineBuffer);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(lineVertices), gl.DYNAMIC_DRAW);

            const posLoc = gl.getAttribLocation(this.lineProgram, 'a_position');
            const colLoc = gl.getAttribLocation(this.lineProgram, 'a_color');

            gl.enableVertexAttribArray(posLoc);
            gl.vertexAttribPointer(posLoc, 3, gl.FLOAT, false, 7 * 4, 0);

            gl.enableVertexAttribArray(colLoc);
            gl.vertexAttribPointer(colLoc, 4, gl.FLOAT, false, 7 * 4, 3 * 4);

            gl.drawArrays(gl.LINES, 0, lineVertices.length / 7);

            gl.disableVertexAttribArray(posLoc);
            gl.disableVertexAttribArray(colLoc);
        }

        const pts = [];
        const currentDynamicNodeRadius = this.currentDynamicNodeRadius || this.nodeRadius;
        this.nodes.forEach(node => {
            const pos = this._getProjectedPosition(node.position);
            if (!pos) return;

            const isHighlighted = this.highlightedNodes.has(node.position);
            const sizeScale = this.is3D ? (600 / (600 + pos.z)) : 1.0;
            const nodeScale = this.nodeScales.has(node.position) ? this.nodeScales.get(node.position) : 1.0;
            const size = currentDynamicNodeRadius * 2.0 * Math.max(0.3, Math.min(2.0, sizeScale)) * (window.devicePixelRatio || 1.0) * nodeScale;
            const opacity = this.is3D ? Math.max(0.2, Math.min(1.0, sizeScale)) : 1.0;

            pts.push({
                x: pos.x,
                y: pos.y,
                z: pos.z,
                r: size,
                opacity: opacity,
                isHighlighted: isHighlighted,
                height: node.height,
                opType: node.opType
            });
        });

        // Depth sort point primitives
        pts.sort((a, b) => b.z - a.z);

        const pointData = [];
        pts.forEach(pt => {
            let r_col, g_col, b_col;
            if (pt.isHighlighted) {
                r_col = isOrange ? (isLight ? 0.917 : 0.968) : (isLight ? 0.02 : 0.06);
                g_col = isOrange ? (isLight ? 0.345 : 0.576) : (isLight ? 0.59 : 0.73);
                b_col = isOrange ? (isLight ? 0.047 : 0.102) : (isLight ? 0.41 : 0.51);
            } else if (pt.opType === 7) {
                /* Drift Certificate leaves: rose #f43f5e (dark) / #e11d48 (light) /
                 * #fb7185 (orange dark) / #e11d48 (orange light) */
                r_col = isOrange ? (isLight ? 0.882 : 0.984) : (isLight ? 0.882 : 0.957);
                g_col = isOrange ? (isLight ? 0.114 : 0.443) : (isLight ? 0.114 : 0.247);
                b_col = isOrange ? (isLight ? 0.282 : 0.522) : (isLight ? 0.282 : 0.369);
            } else if (pt.height === 0) {
                r_col = isOrange ? (isLight ? 0.960 : 0.984) : (isLight ? 0.01 : 0.22); // #f59e0b / #fbbf24
                g_col = isOrange ? (isLight ? 0.619 : 0.749) : (isLight ? 0.52 : 0.74);
                b_col = isOrange ? (isLight ? 0.043 : 0.141) : (isLight ? 0.78 : 0.97);
            } else {
                r_col = isOrange ? (isLight ? 0.811 : 0.658) : (isLight ? 0.49 : 0.65); // #cfcac4 / #a89f91
                g_col = isOrange ? (isLight ? 0.792 : 0.623) : (isLight ? 0.23 : 0.54);
                b_col = isOrange ? (isLight ? 0.768 : 0.568) : (isLight ? 0.93 : 0.98);
            }
            const xa = (pt.x / this.width) * 2 - 1;
            const ya = (1 - pt.y / this.height) * 2 - 1;
            
            // Scale Z coordinates consistently to align points with connection lines in 3D WebGL space
            const z_proj = pt.z / 1000.0;
            
            pointData.push(xa, ya, z_proj, r_col, g_col, b_col, pt.opacity, pt.r);
        });

        if (pointData.length > 0) {
            gl.useProgram(this.pointProgram);
            gl.bindBuffer(gl.ARRAY_BUFFER, this.pointBuffer);
            gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(pointData), gl.DYNAMIC_DRAW);

            const posLoc = gl.getAttribLocation(this.pointProgram, 'a_position');
            const colLoc = gl.getAttribLocation(this.pointProgram, 'a_color');
            const sizeLoc = gl.getAttribLocation(this.pointProgram, 'a_size');

            gl.enableVertexAttribArray(posLoc);
            gl.vertexAttribPointer(posLoc, 3, gl.FLOAT, false, 8 * 4, 0);

            gl.enableVertexAttribArray(colLoc);
            gl.vertexAttribPointer(colLoc, 4, gl.FLOAT, false, 8 * 4, 3 * 4);

            gl.enableVertexAttribArray(sizeLoc);
            gl.vertexAttribPointer(sizeLoc, 1, gl.FLOAT, false, 8 * 4, 7 * 4);

            gl.drawArrays(gl.POINTS, 0, pointData.length / 8);

            gl.disableVertexAttribArray(posLoc);
            gl.disableVertexAttribArray(colLoc);
            gl.disableVertexAttribArray(sizeLoc);
        }
    }

    /* ============================================================================
    * SECTION 4: INTERACTIVE MOUSE, TOUCH & MAGNIFIER CONTROLS
    * ============================================================================ */

    /**
    * @brief Binds mouse and touch listeners for interactive 3D rotation and node hover inspection.
    * @return {void}
    */
    _initMouseEvents() {
        this.canvas.addEventListener('mousedown', (e) => {
            if (!this.is3D) return;
            this.isDragging = true;
            this.wasDragging = false;
            this.lastMouseX = e.clientX;
            this.lastMouseY = e.clientY;
            this.velocityX = 0;
            this.velocityY = 0;
        });

        this.canvas.addEventListener('mousemove', (e) => {
            this.lastClientX = e.clientX;
            this.lastClientY = e.clientY;
            if (this.isLoupeActive) {
                this._updateLoupe(e.clientX, e.clientY);
            }
            if (this.is3D) {
                if (!this.isDragging) return;
                const deltaX = e.clientX - this.lastMouseX;
                const deltaY = e.clientY - this.lastMouseY;

                if (Math.hypot(deltaX, deltaY) > 2) {
                    this.wasDragging = true;
                }

                this.velocityY = deltaX * 0.007;
                this.velocityX = deltaY * 0.007;

                this.angleY += this.velocityY;
                this.angleX += this.velocityX;

                this.angleX = Math.max(-Math.PI / 2.5, Math.min(Math.PI / 2.5, this.angleX));

                this.lastMouseX = e.clientX;
                this.lastMouseY = e.clientY;
                this.draw();
            } else {
                const rect = this.canvas.getBoundingClientRect();
                const x = (e.clientX - rect.left) * (this.width / rect.width);
                const y = (e.clientY - rect.top) * (this.height / rect.height);
                const node = this.getNodeAt(x, y);
                this.canvas.style.cursor = node ? 'pointer' : 'default';
            }
        });

        this.canvas.addEventListener('mouseleave', () => {
            this.lastClientX = null;
            this.lastClientY = null;
            if (this.loupeCanvas) {
                this.loupeCanvas.style.display = 'none';
            }
        });

        this.canvas.addEventListener('touchstart', (e) => {
            if (!this.is3D || e.touches.length === 0) return;
            this.isDragging = true;
            this.wasDragging = false;
            this.lastMouseX = e.touches[0].clientX;
            this.lastMouseY = e.touches[0].clientY;
            this.velocityX = 0;
            this.velocityY = 0;
        });

        this.canvas.addEventListener('touchmove', (e) => {
            if (!this.isDragging || !this.is3D || e.touches.length === 0) return;
            e.preventDefault();
            const deltaX = e.touches[0].clientX - this.lastMouseX;
            const deltaY = e.touches[0].clientY - this.lastMouseY;

            if (Math.hypot(deltaX, deltaY) > 2) {
                this.wasDragging = true;
            }

            this.velocityY = deltaX * 0.007;
            this.velocityX = deltaY * 0.007;

            this.angleY += this.velocityY;
            this.angleX += this.velocityX;

            this.angleX = Math.max(-Math.PI / 2.5, Math.min(Math.PI / 2.5, this.angleX));

            this.lastMouseX = e.touches[0].clientX;
            this.lastMouseY = e.touches[0].clientY;
            this.draw();
        }, { passive: false });

        this.canvas.addEventListener('touchend', () => {
            this.isDragging = false;
        });

        if (!this.windowMouseUpHandler) {
            this.windowMouseUpHandler = () => {
                this.isDragging = false;
            };
            window.addEventListener('mouseup', this.windowMouseUpHandler);
        }

        this.canvas.addEventListener('wheel', (e) => {
            if (!this.is3D) return;
            e.preventDefault();
            this.zoom += e.deltaY * -0.001;
            this.zoom = Math.max(0.4, Math.min(3.0, this.zoom));
            this.draw();
        }, { passive: false });
    }

    _createLoupeElement() {
        const parent = this.canvas.parentElement;
        if (!parent) return;

        let loupe = document.getElementById('mmr-loupe-canvas');
        if (!loupe) {
            loupe = document.createElement('canvas');
            loupe.id = 'mmr-loupe-canvas';
            const loupeSize = 120;
            loupe.width = loupeSize * (window.devicePixelRatio || 1);
            loupe.height = loupeSize * (window.devicePixelRatio || 1);
            loupe.style.width = `${loupeSize}px`;
            loupe.style.height = `${loupeSize}px`;
            loupe.style.position = 'absolute';
            loupe.style.display = 'none';
            loupe.style.pointerEvents = 'none';
            loupe.style.borderRadius = '50%';
            loupe.style.backgroundColor = 'var(--bg-primary)';
            loupe.style.border = '2px solid var(--accent-green)';
            loupe.style.boxShadow = '0 6px 20px rgba(0, 0, 0, 0.6)';
            loupe.style.zIndex = '100';
            parent.appendChild(loupe);
        }
        this.loupeCanvas = loupe;
        this.loupeCtx = loupe.getContext('2d');
    }

    toggleLoupe() {
        this.isLoupeActive = !this.isLoupeActive;
        if (!this.isLoupeActive && this.loupeCanvas) {
            this.loupeCanvas.style.display = 'none';
        } else if (this.isLoupeActive && this.lastClientX !== null && this.lastClientY !== null) {
            this._updateLoupe();
        }
        return this.isLoupeActive;
    }

    _updateLoupe(clientX, clientY) {
        if (!this.isLoupeActive || !this.loupeCanvas) return;

        if (clientX !== undefined && clientY !== undefined) {
            this.lastClientX = clientX;
            this.lastClientY = clientY;
        } else if (this.lastClientX !== null && this.lastClientY !== null) {
            clientX = this.lastClientX;
            clientY = this.lastClientY;
        } else {
            return;
        }

        const rect = this.canvas.getBoundingClientRect();
        if (clientX < rect.left || clientX > rect.right || clientY < rect.top || clientY > rect.bottom) {
            this.loupeCanvas.style.display = 'none';
            return;
        }
        this.loupeCanvas.style.display = 'block';

        const clientWidth = this.canvas.clientWidth || rect.width;
        const clientHeight = this.canvas.clientHeight || rect.height;

        // Convert client coordinates to precise CSS pixels within the canvas container
        const cursorPxX = (clientX - rect.left) * (clientWidth / rect.width);
        const cursorPxY = (clientY - rect.top) * (clientHeight / rect.height);

        const canvasX = (cursorPxX / clientWidth) * this.width;
        const canvasY = (cursorPxY / clientHeight) * this.height;

        const loupeSize = 120;
        let offsetX = cursorPxX - loupeSize / 2;
        let offsetY = cursorPxY - loupeSize / 2;

        // Strictly clamp within canvas viewport so the lens is always 100% visible on the canvas
        const maxOffsetX = clientWidth - loupeSize;
        const maxOffsetY = clientHeight - loupeSize;

        offsetX = Math.max(0, Math.min(maxOffsetX, offsetX));
        offsetY = Math.max(0, Math.min(maxOffsetY, offsetY));

        this.loupeCanvas.style.left = `${offsetX}px`;
        this.loupeCanvas.style.top = `${offsetY}px`;

        const ctx = this.loupeCtx;
        if (!ctx) return;
                         
        const isLight = document.documentElement.classList.contains('light-mode');
        const isOrange = document.documentElement.classList.contains('orange-mode');
        const bgColor = isOrange ? (isLight ? '#fdfbf7' : '#120f0b') : (isLight ? '#f8fafc' : '#0f172a');
        const dpr = window.devicePixelRatio || 1;

        ctx.save();
        ctx.clearRect(0, 0, loupeSize * dpr, loupeSize * dpr);
        ctx.beginPath();
        ctx.arc((loupeSize * dpr) / 2, (loupeSize * dpr) / 2, (loupeSize * dpr) / 2 - 2, 0, Math.PI * 2);
        ctx.clip();

        // Render solid opaque background so underlying canvas does not bleed through
        ctx.fillStyle = bgColor;
        ctx.fillRect(0, 0, loupeSize * dpr, loupeSize * dpr);

        const zoom = 2.5;
        const sWidth = (loupeSize / zoom) * dpr * (this.width / clientWidth);
        const sHeight = (loupeSize / zoom) * dpr * (this.height / clientHeight);
        let srcX = canvasX * dpr - sWidth / 2;
        let srcY = canvasY * dpr - sHeight / 2;
        let srcW = sWidth;
        let srcH = sHeight;

        let dstX = 0;
        let dstY = 0;
        let dstW = loupeSize * dpr;
        let dstH = loupeSize * dpr;

        // Handle safe sub-rectangle clipping for peripheral edge nodes
        if (srcX < 0) {
            const diff = -srcX;
            dstX += (diff / srcW) * dstW;
            dstW -= (diff / srcW) * dstW;
            srcW -= diff;
            srcX = 0;
        }
        if (srcY < 0) {
            const diff = -srcY;
            dstY += (diff / srcH) * dstH;
            dstH -= (diff / srcH) * dstH;
            srcH -= diff;
            srcY = 0;
        }
        if (srcX + srcW > this.canvas.width) {
            const diff = (srcX + srcW) - this.canvas.width;
            dstW -= (diff / srcW) * dstW;
            srcW -= diff;
        }
        if (srcY + srcH > this.canvas.height) {
            const diff = (srcY + srcH) - this.canvas.height;
            dstH -= (diff / srcH) * dstH;
            srcH -= diff;
        }

        if (srcW > 0 && srcH > 0 && dstW > 0 && dstH > 0) {
            ctx.drawImage(this.canvas, srcX, srcY, srcW, srcH, dstX, dstY, dstW, dstH);
        }

        ctx.strokeStyle = isOrange
            ? (isLight ? 'rgba(234, 88, 12, 0.8)' : 'rgba(247, 147, 26, 0.8)')
            : (isLight ? 'rgba(5, 150, 105, 0.8)' : 'rgba(16, 185, 129, 0.8)');
        ctx.lineWidth = 2 * dpr;
        ctx.beginPath();
        ctx.arc((loupeSize * dpr) / 2, (loupeSize * dpr) / 2, 5 * dpr, 0, Math.PI * 2);
        ctx.stroke();

        ctx.restore();
    }

    zoomIn() {
        if (!this.is3D) return;
        this.zoom = Math.min(3.0, this.zoom + 0.1);
        this.draw();
    }

    zoomOut() {
        if (!this.is3D) return;
        this.zoom = Math.max(0.4, this.zoom - 0.1);
        this.draw();
    }

    resetRotation() {
        if (!this.is3D) return;
        this.angleX = -0.3;
        this.angleY = 0.4;
        this.zoom = 1.0;
        this.velocityX = 0;
        this.velocityY = 0;
        this.draw();
    }

    /**
     * Applies dynamic perspective projection to standard nodes inside 3D space
     */
    _getProjectedPosition(position) {
        const raw = this.positions.get(position);
        if (!raw) return null;
        if (!this.is3D) return { x: raw.x, y: raw.y, z: 0 };

        const cx = this.width / 2;
        const cy = this.height / 2;

        const x0 = raw.x - cx;
        const y0 = raw.y - cy;

        // Depth projection using topological position offsets to create mountain peaks depth
        const node = this.nodesMap ? this.nodesMap.get(position) : null;
        const currentDynamicRowHeight = this.currentDynamicRowHeight || this.rowHeight;
        const z0 = node ? (node.height * (currentDynamicRowHeight * 0.4) - (node.position % 5) * 15) : 0;

        // Rotation around X axis
        const cosX = Math.cos(this.angleX);
        const sinX = Math.sin(this.angleX);
        const x1 = x0;
        const y1 = y0 * cosX - z0 * sinX;
        const z1 = y0 * sinX + z0 * cosX;

        // Rotation around Y axis
        const cosY = Math.cos(this.angleY);
        const sinY = Math.sin(this.angleY);
        const x2 = x1 * cosY + z1 * sinY;
        const y2 = y1;
        const z2 = -x1 * sinY + z1 * cosY;

        // Perspective Projection Math
        const fov = 600;
        /* Guard the projection denominator: idle auto-rotation drives yaw
         * through ±90° every ~13s, where (fov + z2) crosses zero for edge
         * nodes — exploding |scale| or mirroring the tree. Clamping keeps the
         * perspective monotonic and bounded (scale <= 4). */
        const scale = fov / Math.max(fov * 0.25, fov + z2);

        return {
            x: cx + x2 * scale * this.zoom,
            y: cy + y2 * scale * this.zoom,
            z: z2
        };
    }

    /**
     * Updates the local MMR node array and recalculates coordinates.
     * @param {Array<Object>} nodesList - The serialized nodes from the block queries.
     */
    setNodes(nodesList) {
        const oldPositions = new Set(this.positions.keys());
        this.nodes = nodesList;
        this.nodesMap = new Map();
        nodesList.forEach(node => {
            this.nodesMap.set(node.position, node);
        });
        this.positions.clear();
        this._calculateCoordinates();
       
        // Skip 20-frame scale animations when syncing large batches of nodes to prevent animation thrash
        const isBulk = (nodesList.length - oldPositions.size) > 25;
        this.nodes.forEach(node => {
            if (!oldPositions.has(node.position)) {
                this.nodeScales.set(node.position, isBulk ? 1.0 : 0.0);
            } else if (!this.nodeScales.has(node.position)) {
                this.nodeScales.set(node.position, 1.0);
            }
        });

        this.draw();
        if (!isBulk) {
            this._startAnimationLoop();
        }
    }

    /**
     * Detects if a node is at the given coordinates (x, y).
     * @param {number} x
     * @param {number} y
     * @returns {Object|null}
     */
    getNodeAt(x, y) {
        if (this.wasDragging) {
            this.wasDragging = false;
            return null;
        }
        const currentDynamicNodeRadius = this.currentDynamicNodeRadius || this.nodeRadius;
        let closestNode = null;
        let minDistance = Infinity;

        for (const node of this.nodes) {
            const pos = this._getProjectedPosition(node.position);
            if (pos) {
                const dist = Math.hypot(pos.x - x, pos.y - y);
                const sizeScale = this.is3D ? (600 / (600 + pos.z)) : 1.0;
                const r = currentDynamicNodeRadius * Math.max(0.3, Math.min(2.0, sizeScale));
                const hitRadius = Math.max(r + 6, 12);
                if (dist <= hitRadius && dist < minDistance) {
                    minDistance = dist;
                    closestNode = node;
                }
            }
        }
        return closestNode;
    }

    /**
     * Highlights a matched leaf commitment and begins a progressive animation
     * of its proof path up to its respective tree peak.
     * @param {number} leafPosition - The index position of the matched leaf node.
     * @param {Array<number>} proofPath - List of position indices in the proof path.
     */
    animateProofPath(leafPosition, proofPath) {
        this.highlightedNodes.clear();
        this.activePathEdges = [];
        this.targetPeaks = [];

        this.highlightedNodes.add(leafPosition);

        let current = leafPosition;
        for (let i = 0; i < proofPath.length; i++) {
            const sibling = proofPath[i];
            const parent = this._findParent(current, sibling);
            if (parent !== -1) {
                this.activePathEdges.push({
                    from: current,
                    to: parent,
                    sibling: sibling,
                    progress: 0.0
                });
                current = parent;
            } else {
                this.targetPeaks.push(sibling);
            }
        }
        this.targetPeaks.push(current);

        this._startAnimationLoop();
    }

    /* ============================================================================
    * SECTION 5: TOPOGRAPHICAL TREE LAYOUT & PROOF ANIMATION
    * ============================================================================ */

   /**
    * @brief Calculates screen coordinates for all MMR nodes using hierarchical tree layout rules.
    *
    * @details
    * 1. Positions leaves (height 0) along the bottom row with dynamic spacing to fit container width.
    * 2. Adjusts dynamic node radius proportionally to prevent overlap in high-leaf trees.
    * 3. Centers parent nodes horizontally at the midpoint of their left and right children.
    *
    * @return {void}
    * @complexity Time: O(nodes.length), Space: O(nodes.length).
    */
   _calculateCoordinates() {
        if (this.nodes.length === 0) return;

        // Adapt padding dynamically to maintain proportion on low-height mobile landscape screens
        const padX = Math.max(16, Math.min(this.paddingX, this.width * 0.05));
        const padY = Math.max(18, Math.min(this.paddingY, this.height * 0.12));

        // Extract leaves (height 0) to align the bottom row
        const leaves = this.nodes.filter(n => n.height === 0).sort((a, b) => a.position - b.position);

        // Dynamically compute leaf spacing to ensure they fit within the canvas boundaries without running off-screen
        const leafCount = leaves.length;
        const availableWidth = this.width - 2 * padX;
        const dynamicSpacing = leafCount > 1 ? availableWidth / (leafCount - 1) : availableWidth;
        const spacing = Math.min(this.leafSpacing, dynamicSpacing);

        // Dynamically resize node radius to maintain proportions and eliminate overlap as leaf count increases
        this.currentDynamicNodeRadius = Math.max(2.5, Math.min(this.nodeRadius, spacing * 0.38));

        // Center the tree layout horizontally inside the canvas
        const totalTreeWidth = (leafCount - 1) * spacing;
        const startX = padX + (availableWidth - totalTreeWidth) / 2;

        // Map leaves evenly along the X axis
        leaves.forEach((leaf, index) => {
            const x = startX + index * spacing;
            const y = this.height - padY;
            this.positions.set(leaf.position, { x, y });
        });

        // Compute parent positions based on their children's midpoints (non-allocating loop)
        let maxHeights = 0;
        for (let i = 0; i < this.nodes.length; i++) {
            if (this.nodes[i].height > maxHeights) maxHeights = this.nodes[i].height;
        }
        this.currentDynamicRowHeight = this.rowHeight;
        if (maxHeights > 0) {
            const availableHeight = this.height - 2 * padY;
            this.currentDynamicRowHeight = Math.min(this.rowHeight, availableHeight / maxHeights);
        }
        for (let h = 1; h <= maxHeights; h++) {
            const levelNodes = this.nodes.filter(n => n.height === h);
            levelNodes.forEach(node => {
                if (node.leftChild !== -1 && node.rightChild !== -1) {
                    const leftPos = this.positions.get(node.leftChild);
                    const rightPos = this.positions.get(node.rightChild);
                    if (leftPos && rightPos) {
                        const x = (leftPos.x + rightPos.x) / 2;
                        const y = this.height - padY - (h * this.currentDynamicRowHeight);
                        this.positions.set(node.position, { x, y });
                    }
                }
            });
        }
    }

    /**
     * @brief Resolves the common parent node position of two child nodes.
     * @param {number} childA First child position index.
     * @param {number} childB Second child position index.
     * @return {number} Parent position index, or -1 if not merged.
     */
    _findParent(childA, childB) {
        const match = this.nodes.find(n =>
            (n.leftChild === childA && n.rightChild === childB) ||
            (n.leftChild === childB && n.rightChild === childA)
        );
        return match ? match.position : -1;
    }

    /**
     * @brief Redraws the complete MMR topography matrix in 2D Canvas mode.
     * @return {void}
     * @complexity Time: O(nodes.length), Space: O(1).
     */
    draw() {
        this._resizeCanvas();
        if (this.is3D && this.gl) {
            this._drawWebGL();
            if (this.isLoupeActive && this.lastClientX !== null && this.lastClientY !== null) {
                this._updateLoupe();
            }
            return;
        }

        if (!this.ctx) return;
        this.ctx.clearRect(0, 0, this.width, this.height);

        if (this.nodes.length === 0) {
            this.ctx.fillStyle = document.documentElement.classList.contains('light-mode') ? '#475569' : '#94a3b8';
            this.ctx.font = '14px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.fillText("Syncing Blockchain Topography...", this.width / 2, this.height / 2);
            return;
        }

        // Depth sort nodes if in 3D mode to ensure correct overlapping
        let renderNodes = [...this.nodes];
        if (this.is3D) {
            renderNodes.sort((a, b) => {
                const posA = this._getProjectedPosition(a.position);
                const posB = this._getProjectedPosition(b.position);
                if (!posA || !posB) return 0;
                return posB.z - posA.z; // Draw background (large Z) first
            });
        }

        const isLight = document.documentElement.classList.contains('light-mode');
        const isOrange = document.documentElement.classList.contains('orange-mode');

        // Draw standard connection lines (Batched into a single draw call in 2D mode)
        if (!this.is3D) {
            this.ctx.beginPath();
            this.ctx.strokeStyle = isOrange ? (isLight ? '#e7e5e4' : '#342a21') : (isLight ? '#cbd5e1' : '#475569');
            this.ctx.lineWidth = 1.5;
            for (let i = 0; i < this.nodes.length; i++) {
                const node = this.nodes[i];
                if (node.parent !== -1) {
                    const start = this.positions.get(node.position);
                    const end = this.positions.get(node.parent);
                    if (start && end) {
                        this.ctx.moveTo(start.x, start.y);
                        this.ctx.lineTo(end.x, end.y);
                    }
                }
            }
            this.ctx.stroke();
        } else {
            this.nodes.forEach(node => {
                if (node.parent !== -1) {
                    const start = this._getProjectedPosition(node.position);
                    const end = this._getProjectedPosition(node.parent);
                    if (start && end) {
                        this.ctx.beginPath();
                        this.ctx.moveTo(start.x, start.y);
                        this.ctx.lineTo(end.x, end.y);
                        const avgZ = (start.z + end.z) / 2;
                        const scale = 600 / (600 + avgZ);
                        const opacity = Math.max(0.1, Math.min(1.0, scale));
                        this.ctx.strokeStyle = isOrange
                            ? (isLight ? `rgba(231, 229, 228, ${opacity})` : `rgba(52, 42, 33, ${opacity})`)
                            : (isLight ? `rgba(148, 163, 184, ${opacity})` : `rgba(71, 85, 105, ${opacity})`);
                        this.ctx.lineWidth = 1.5 * Math.max(0.3, Math.min(2.0, scale));
                        this.ctx.stroke();
                    }
                }
            });
        }

        // Draw animated proof paths
        this.activePathEdges.forEach(edge => {
            const start = this._getProjectedPosition(edge.from);
            const end = this._getProjectedPosition(edge.to);
            if (start && end) {
                if (this.is3D) {
                    const avgZ = (start.z + end.z) / 2;
                    const scale = 600 / (600 + avgZ);
                    const opacity = Math.max(0.2, Math.min(1.0, scale));
                    this.ctx.strokeStyle = isOrange
                        ? (isLight ? `rgba(234, 88, 12, ${opacity})` : `rgba(247, 147, 26, ${opacity})`)
                        : (isLight ? `rgba(5, 150, 105, ${opacity})` : `rgba(16, 185, 129, ${opacity})`);
                    this.ctx.lineWidth = 3.0 * Math.max(0.3, Math.min(2.0, scale));
                } else {
                    this.ctx.strokeStyle = isOrange ? (isLight ? '#ea580c' : '#f7931a') : (isLight ? '#059669' : '#10b981');
                    this.ctx.lineWidth = 3.0;
                }
                this.ctx.beginPath();
                this.ctx.moveTo(start.x, start.y);

                const curX = start.x + (end.x - start.x) * edge.progress;
                const curY = start.y + (end.y - start.y) * edge.progress;
                this.ctx.lineTo(curX, curY);
                this.ctx.stroke();
            }
        });

        // Draw node circles (Batched by color into single fill/stroke calls in 2D)
        const currentDynamicNodeRadius = this.currentDynamicNodeRadius || this.nodeRadius;
        if (!this.is3D) {
            const leafColor = isOrange ? (isLight ? '#f59e0b' : '#fbbf24') : (isLight ? '#0284c7' : '#38bdf8');
            const leafBorder = isOrange ? (isLight ? '#d97706' : '#f59e0b') : (isLight ? '#0369a1' : '#0284c7');
            const parentColor = isOrange ? (isLight ? '#d6d3d1' : '#a89f91') : (isLight ? '#7c3aed' : '#a78bfa');
            const parentBorder = isOrange ? (isLight ? '#a8a29e' : '#78716c') : (isLight ? '#6d28d9' : '#7c3aed');
            const highlightColor = isOrange ? (isLight ? '#ea580c' : '#f7931a') : (isLight ? '#059669' : '#10b981');
            const highlightBorder = isOrange ? (isLight ? '#c2410c' : '#b45309') : (isLight ? '#047857' : '#059669');
            /* Drift Certificate leaves (OP_APPLY_DRIFT_CERT): rose accent — the only
             * hue family unused by the renderer (leaves sky-blue, peaks violet,
             * proof highlight emerald) so anchors stand out in every theme. */
            const driftLeafColor = isOrange ? (isLight ? '#e11d48' : '#fb7185') : (isLight ? '#e11d48' : '#f43f5e');
            const driftLeafBorder = isOrange ? (isLight ? '#9f1239' : '#f43f5e') : (isLight ? '#9f1239' : '#e11d48');

            // 1. Standard Leaves
            this.ctx.beginPath();
            this.ctx.fillStyle = leafColor;
            this.ctx.strokeStyle = leafBorder;
            for (let i = 0; i < this.nodes.length; i++) {
                const node = this.nodes[i];
                if (node.height === 0 && node.opType !== 7 && !this.highlightedNodes.has(node.position)) {
                    const pos = this.positions.get(node.position);
                    if (pos) {
                        const nodeScale = this.nodeScales.get(node.position) ?? 1.0;
                        const r = currentDynamicNodeRadius * nodeScale;
                        this.ctx.moveTo(pos.x + r, pos.y);
                        this.ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI);
                    }
                }
            }
            this.ctx.fill();
            this.ctx.stroke();

            // 1b. Drift Certificate Leaves (OP_APPLY_DRIFT_CERT)
            this.ctx.beginPath();
            this.ctx.fillStyle = driftLeafColor;
            this.ctx.strokeStyle = driftLeafBorder;
            for (let i = 0; i < this.nodes.length; i++) {
                const node = this.nodes[i];
                if (node.height === 0 && node.opType === 7 && !this.highlightedNodes.has(node.position)) {
                    const pos = this.positions.get(node.position);
                    if (pos) {
                        const nodeScale = this.nodeScales.get(node.position) ?? 1.0;
                        const r = currentDynamicNodeRadius * nodeScale * 1.15;
                        this.ctx.moveTo(pos.x + r, pos.y);
                        this.ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI);
                    }
                }
            }
            this.ctx.fill();
            this.ctx.stroke();

            // 2. Internal / Peak Nodes
            this.ctx.beginPath();
            this.ctx.fillStyle = parentColor;
            this.ctx.strokeStyle = parentBorder;
            for (let i = 0; i < this.nodes.length; i++) {
                const node = this.nodes[i];
                if (node.height > 0 && !this.highlightedNodes.has(node.position)) {
                    const pos = this.positions.get(node.position);
                    if (pos) {
                        const nodeScale = this.nodeScales.get(node.position) ?? 1.0;
                        const r = currentDynamicNodeRadius * nodeScale;
                        this.ctx.moveTo(pos.x + r, pos.y);
                        this.ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI);
                    }
                }
            }
            this.ctx.fill();
            this.ctx.stroke();

            // 3. Highlighted Nodes
            if (this.highlightedNodes.size > 0) {
                this.ctx.beginPath();
                this.ctx.fillStyle = highlightColor;
                this.ctx.strokeStyle = highlightBorder;
                for (const posIdx of this.highlightedNodes) {
                    const pos = this.positions.get(posIdx);
                    if (pos) {
                        const r = currentDynamicNodeRadius;
                        this.ctx.moveTo(pos.x + r, pos.y);
                        this.ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI);
                    }
                }
                this.ctx.fill();
                this.ctx.stroke();
            }
        } else {
            renderNodes.forEach(node => {
                const pos = this._getProjectedPosition(node.position);
                if (!pos) return;

                const isHighlighted = this.highlightedNodes.has(node.position);
                const sizeScale = 600 / (600 + pos.z);
                const nodeScale = this.nodeScales.get(node.position) ?? 1.0;
                const r = currentDynamicNodeRadius * Math.max(0.3, Math.min(2.0, sizeScale)) * nodeScale;
                const opacity = Math.max(0.2, Math.min(1.0, sizeScale));

                this.ctx.save();
                this.ctx.globalAlpha = opacity;
                this.ctx.beginPath();
                this.ctx.arc(pos.x, pos.y, r, 0, 2 * Math.PI);

                if (isHighlighted) {
                    this.ctx.fillStyle = isOrange ? (isLight ? '#ea580c' : '#f7931a') : (isLight ? '#059669' : '#10b981');
                    this.ctx.strokeStyle = isOrange ? (isLight ? '#c2410c' : '#b45309') : (isLight ? '#047857' : '#059669');
                } else if (node.height === 0 && node.opType === 7) {
                    this.ctx.fillStyle = isOrange ? (isLight ? '#e11d48' : '#fb7185') : (isLight ? '#e11d48' : '#f43f5e');
                    this.ctx.strokeStyle = isOrange ? (isLight ? '#9f1239' : '#f43f5e') : (isLight ? '#9f1239' : '#e11d48');
                } else if (node.height === 0) {
                    this.ctx.fillStyle = isOrange ? (isLight ? '#f59e0b' : '#fbbf24') : (isLight ? '#0284c7' : '#38bdf8');
                    this.ctx.strokeStyle = isOrange ? (isLight ? '#d97706' : '#f59e0b') : (isLight ? '#0369a1' : '#0284c7');
                } else {
                    this.ctx.fillStyle = isOrange ? (isLight ? '#d6d3d1' : '#a89f91') : (isLight ? '#7c3aed' : '#a78bfa');
                    this.ctx.strokeStyle = isOrange ? (isLight ? '#a8a29e' : '#78716c') : (isLight ? '#6d28d9' : '#7c3aed');
                }

                this.ctx.fill();
                this.ctx.stroke();
                this.ctx.restore();
            });
        }

        if (this.isLoupeActive && this.lastClientX !== null && this.lastClientY !== null) {
            this._updateLoupe();
        }
    }

    _startAnimationLoop() {
        if (this.is3D) {
            // 3D loop already runs continuously, so no need to spawn a separate one
            return;
        }
        if (!this.isTabVisible) return;
        if (this.animationFrameId) {
            cancelAnimationFrame(this.animationFrameId);
        }

        const updateAndDraw = () => {
            let animating = false;

            for (let i = 0; i < this.activePathEdges.length; i++) {
                const edge = this.activePathEdges[i];
                if (edge.progress < 1.0) {
                    // Check if previous link in path is finished
                    if (i === 0 || this.activePathEdges[i - 1].progress >= 1.0) {
                        edge.progress += 0.05; // Animation speed
                        if (edge.progress >= 1.0) {
                            edge.progress = 1.0;
                            this.highlightedNodes.add(edge.to);
                            this.highlightedNodes.add(edge.sibling);
                            
                            // If this is the last edge in the path, highlight the peaks to complete the proof visualization
                            if (i === this.activePathEdges.length - 1 && this.targetPeaks) {
                                this.targetPeaks.forEach(p => this.highlightedNodes.add(p));
                            }
                        }
                        animating = true;
                    }
                }
            }
            
            // If the leaf is already a peak, immediately highlight all peaks
            if (this.activePathEdges.length === 0 && this.targetPeaks) {
                this.targetPeaks.forEach(p => this.highlightedNodes.add(p));
            }

            let scalesAnimating = false;
            this.nodeScales.forEach((scale, pos) => {
                if (scale < 1.0) {
                    scale += 0.05;
                    if (scale >= 1.0) scale = 1.0;
                    this.nodeScales.set(pos, scale);
                    scalesAnimating = true;
                }
            });
            animating = animating || scalesAnimating;

            this.draw();

            if (animating) {
                this.animationFrameId = requestAnimationFrame(updateAndDraw);
            } else {
                this.animationFrameId = null;
            }
        };

        this.animationFrameId = requestAnimationFrame(updateAndDraw);
    }

    _start3DLoop() {
        if (!this.is3D) return;
        if (!this.isTabVisible) return;
        if (this.animationFrameId) {
            cancelAnimationFrame(this.animationFrameId);
        }
        
        const tick = () => {
            if (!this.is3D || !this.isTabVisible) {
                this.animationFrameId = null;
                return;
            }

            if (this.isDragging) {
                this.velocityX *= 0.8;
                this.velocityY *= 0.8;
            } else {
                this.angleY += this.velocityY;
                this.angleX += this.velocityX;
                
                this.velocityX *= 0.95;
                this.velocityY *= 0.95;
                
                if (Math.hypot(this.velocityX, this.velocityY) < 0.001) {
                    this.angleY += 0.002;
                }
            }
            this.angleX = Math.max(-Math.PI / 2.5, Math.min(Math.PI / 2.5, this.angleX));

            // Update proof path progress if active
            for (let i = 0; i < this.activePathEdges.length; i++) {
                const edge = this.activePathEdges[i];
                if (edge.progress < 1.0) {
                    if (i === 0 || this.activePathEdges[i - 1].progress >= 1.0) {
                        edge.progress += 0.05;
                        if (edge.progress >= 1.0) {
                            edge.progress = 1.0;
                            this.highlightedNodes.add(edge.to);
                            this.highlightedNodes.add(edge.sibling);
                            
                            // If this is the last edge in the path, highlight the peaks to complete the proof visualization
                            if (i === this.activePathEdges.length - 1 && this.targetPeaks) {
                                this.targetPeaks.forEach(p => this.highlightedNodes.add(p));
                            }
                        }
                    }
                }
            }
            
            // If the leaf is already a peak, immediately highlight all peaks
            if (this.activePathEdges.length === 0 && this.targetPeaks) {
                this.targetPeaks.forEach(p => this.highlightedNodes.add(p));
            }

            this.nodeScales.forEach((scale, pos) => {
                if (scale < 1.0) {
                    scale += 0.05;
                    if (scale >= 1.0) scale = 1.0;
                    this.nodeScales.set(pos, scale);
                }
            });

            this.draw();
            this.animationFrameId = requestAnimationFrame(tick);
        };
        
        this.animationFrameId = requestAnimationFrame(tick);
    }

    /**
     * Terminate rendering and clear queues.
     */
    destroy() {
        if (this.animationFrameId) {
            cancelAnimationFrame(this.animationFrameId);
        }
        if (this.visibilityHandler) {
            document.removeEventListener('visibilitychange', this.visibilityHandler);
        }
        if (this.windowMouseUpHandler) {
            window.removeEventListener('mouseup', this.windowMouseUpHandler);
        }
        if (this.resizeObserver) {
            this.resizeObserver.disconnect();
            this.resizeObserver = null;
        }
        if (this.orientationHandler) {
            window.removeEventListener('orientationchange', this.orientationHandler);
            window.removeEventListener('resize', this.orientationHandler);
        }
        if (this.gl) {
            const gl = this.gl;
            if (this.pointBuffer) gl.deleteBuffer(this.pointBuffer);
            if (this.lineBuffer) gl.deleteBuffer(this.lineBuffer);
            if (this.pointProgram) gl.deleteProgram(this.pointProgram);
            if (this.lineProgram) gl.deleteProgram(this.lineProgram);
        }
        if (this.loupeCanvas && this.loupeCanvas.parentElement) {
            this.loupeCanvas.parentElement.removeChild(this.loupeCanvas);
            this.loupeCanvas = null;
        }
        this.positions.clear();
        this.highlightedNodes.clear();
        this.activePathEdges = [];
        this.nodeScales.clear();
    }
}

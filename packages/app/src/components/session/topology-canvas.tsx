/**
 * topology-canvas.tsx
 *
 * Componente de topología de red para el panel derecho del SOC dashboard.
 *
 * Arquitectura de rendimiento — mismo patrón que AnalysisAgentView.tsx
 * (proyecto_ciberseguridad):
 *
 * 1. panRef / scaleRef  → mutables durante drag/wheel (sin setState)
 * 2. DOM mutation directa en el stage y el shell → 120 FPS en panning
 * 3. setPan/setScale solo al soltar el puntero (un único re-render)
 * 4. wheel: non-passive listener (e.preventDefault() garantizado)
 * 5. will-change: transform en el stage (GPU layer)
 * 6. WCAG: role="region", aria-label, aria-busy, aria-live, focus-visible
 *
 * CSS → topology-canvas.css (clases BEM `.topo-*`, @layer components)
 */

import { createSignal, onMount, onCleanup, For, Show, createMemo, createEffect } from "solid-js";
import "./topology-canvas.css";
import { Icon } from "@argos/ui/icon";
import { type Device, DEFAULT_RISKY_PORTS } from "./topology-data";
import { useLanguage } from "@/context/language";

export type { Device } from "./topology-data";

// ── Dimensiones lógicas del canvas (pre-transform) ────────────────────────────
const CW = 2400;
const CH = 1200;
const GX = 1200;
const GY = 600;

// ── Helpers ───────────────────────────────────────────────────────────────────

function isVulnerable(d: Device, riskyPorts: Set<number>) {
  return d.openPorts?.some((p) => riskyPorts.has(p)) ?? false;
}

/** Resuelve un token CSS a un color literal para canvas (con fallback). */
function canvasColor(name: string, fallback: string) {
  if (typeof document === "undefined") return fallback
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value || fallback
}

/** Colores del renderer canvas — resueltos una vez desde los tokens del tema. */
function resolveCanvasColors() {
  return {
    edge: canvasColor("--border-weaker-base", "transparent"),
    edgeRisky: canvasColor("--state-fg-danger", "currentColor"),
    gatewayFill: canvasColor("--bg-base", "transparent"),
    gatewayStroke: canvasColor("--state-fg-success", "currentColor"),
    node: canvasColor("--state-fg-success", "currentColor"),
    nodeRisky: canvasColor("--state-fg-danger", "currentColor"),
  }
}

/** Distribuye N nodos en elipse alrededor del gateway con separación mínima. */
function radialPositions(count: number) {
  const rx = 720, ry = 400;
  const positions = Array.from({ length: count }, (_, i) => {
    const a = (2 * Math.PI * i) / count - Math.PI / 2;
    return { x: GX + rx * Math.cos(a), y: GY + ry * Math.sin(a) };
  });

  // Separación iterativa — evita solapamiento entre tarjetas.
  // Encima de ~150 dispositivos el coste O(n²) por iteración bloquea el hilo
  // principal: se reduce el nº de iteraciones manteniendo un presupuesto de
  // trabajo par-a-par acotado (solo cambia el layout microscópicamente >150).
  const maxIterations = count <= 150 ? 60 : Math.max(2, Math.min(60, Math.floor(1340000 / (count * count))));
  for (let iter = 0; iter < maxIterations; iter++) {
    let moved = false;
    for (let i = 0; i < count; i++) {
      for (let j = i + 1; j < count; j++) {
        const p1 = positions[i], p2 = positions[j];
        const dx = p2.x - p1.x, dy = p2.y - p1.y;
        const minX = 300, minY = 170;
        if (Math.abs(dx) < minX && Math.abs(dy) < minY) {
          moved = true;
          const ox = (minX - Math.abs(dx)) * 0.5;
          const oy = (minY - Math.abs(dy)) * 0.5;
          const sx = dx === 0 ? 1 : Math.sign(dx);
          const sy = dy === 0 ? 1 : Math.sign(dy);
          p1.x -= sx * ox; p1.y -= sy * oy;
          p2.x += sx * ox; p2.y += sy * oy;
        }
      }
    }
    if (!moved) break;
  }

  // Clamp dentro del canvas lógico
  return positions.map((p) => ({
    x: Math.max(160, Math.min(p.x, CW - 160)),
    y: Math.max(120, Math.min(p.y, CH - 120)),
  }));
}

/**
 * Bézier cúbica con control-points adaptativos al lado de salida/entrada.
 * Idéntica a la usada en AnalysisAgentView / red.js.
 */
function bezierPath(x0: number, y0: number, x1: number, y1: number, side0: "left" | "right", side1: "left" | "right") {
  const dx = Math.abs(x1 - x0), dy = Math.abs(y1 - y0);
  const off = Math.max(60, Math.min(200, (dx + dy) * 0.28));
  const cp0x = side0 === "right" ? x0 + off : x0 - off;
  const cp1x = side1 === "left"  ? x1 - off : x1 + off;
  return `M ${x0} ${y0} C ${cp0x} ${y0} ${cp1x} ${y1} ${x1} ${y1}`;
}

// ── Componente ────────────────────────────────────────────────────────────────
export function TopologyCanvas(props: { devices?: Device[]; gateway?: Device; riskyPorts?: Set<number> }) {
  const language = useLanguage();
  let shellRef!: HTMLDivElement;
  let stageRef!: HTMLDivElement;

  const riskyPorts = () => props.riskyPorts ?? DEFAULT_RISKY_PORTS;

  // Estado React solo para HUD y re-render mínimo
  const [scale, setScale]   = createSignal(1);
  const [isPanning, setIsPanning] = createSignal(false);

  // Refs mutables — se actualizan durante el drag sin causar re-renders
  const panRef   = { x: 0, y: 0 };
  const scaleRef = { v: 1 };
  // Referencia al estado de arrastre activo
  const panStart = { mx: 0, my: 0, px: 0, py: 0 };
  let isPanningRef = false;

  const devices   = () => props.devices ?? [];
  const gateway   = () => props.gateway;
  const hostCount = () => devices().length + (gateway() ? 1 : 0);
  const isEmpty   = () => hostCount() === 0;
  const positions = createMemo(() => radialPositions(devices().length));

  // ── Utilidad: aplica transform+dot-grid directamente al DOM ───────────────
  const applyTransform = (px: number, py: number, sc: number) => {
    if (stageRef) {
      stageRef.style.transform = `translate(${px}px, ${py}px) scale(${sc})`;
    }
    if (shellRef) {
      shellRef.style.backgroundPosition =
        `${px - 24 * sc}px ${py - 24 * sc}px`;
      shellRef.style.backgroundSize = `${48 * sc}px ${48 * sc}px`;
    }
  };

  // ── Auto-fit: calcula escala/pan óptimos para que el canvas quepa ─────────
  const centerFit = () => {
    if (!shellRef) return;
    const w = shellRef.clientWidth, h = shellRef.clientHeight;
    if (!w || !h) return;

    const s = Math.max(0.15, Math.min((w - 40) / CW, (h - 40) / CH, 1));
    const px = (w - CW * s) / 2;
    const py = (h - CH * s) / 2;

    panRef.x = px; panRef.y = py; scaleRef.v = s;
    applyTransform(px, py, s);
    setScale(s); // actualiza HUD zoom %
  };

  onMount(() => {
    centerFit();

    // ResizeObserver — re-centra al cambiar tamaño del panel
    const ro = new ResizeObserver(() => requestAnimationFrame(centerFit));
    ro.observe(shellRef);

    // Wheel — NON-PASSIVE, necesario para e.preventDefault()
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const curS = scaleRef.v;
      // Factor natural: deltaY>0 = alejarse
      const factor = 1 - e.deltaY * 0.001;
      const newS   = Math.max(0.1, Math.min(5, curS * factor));
      const rect   = shellRef.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;

      // Zoom centrado en cursor (Figma-style)
      const px = cx - (newS / curS) * (cx - panRef.x);
      const py = cy - (newS / curS) * (cy - panRef.y);

      panRef.x = px; panRef.y = py; scaleRef.v = newS;
      applyTransform(px, py, newS);
      setScale(newS); // actualiza HUD
    };

    shellRef.addEventListener("wheel", onWheel, { passive: false });

    onCleanup(() => {
      ro.disconnect();
      shellRef.removeEventListener("wheel", onWheel);
    });
  });

  // ── Pointer handlers (Pan del lienzo) ─────────────────────────────────────
  const onPointerDown = (e: PointerEvent) => {
    const target = e.target as HTMLElement;
    // No iniciar paneo si el click es sobre un elemento interactivo
    if (target.closest("button, a, input, textarea, select")) return;

    e.preventDefault(); // evita selección de texto durante drag
    shellRef.setPointerCapture(e.pointerId);

    isPanningRef = true;
    setIsPanning(true);
    panStart.mx = e.clientX; panStart.my = e.clientY;
    panStart.px = panRef.x; panStart.py = panRef.y;
  };

  const onPointerMove = (e: PointerEvent) => {
    if (!isPanningRef) return;
    // Pan en píxeles de pantalla (no dividimos por escala: translate es screen-space)
    const px = panStart.px + (e.clientX - panStart.mx);
    const py = panStart.py + (e.clientY - panStart.my);

    panRef.x = px; panRef.y = py;

    // Mutación directa → sin setState → 120 FPS
    applyTransform(px, py, scaleRef.v);
  };

  const onPointerUp = (e: PointerEvent) => {
    if (!isPanningRef) return;
    shellRef.releasePointerCapture(e.pointerId);
    isPanningRef = false;
    setIsPanning(false);
    // Un único re-render al soltar para sincronizar el estado React
    setScale(scaleRef.v);
  };

  return (
    <div
      ref={shellRef}
      class={`topo-shell${isPanning() ? " is-panning" : ""}`}
      role="region"
      aria-label={language.t("topology.canvas.ariaLabel")}
      aria-busy="false"
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onDblClick={centerFit}
      onKeyDown={(e) => {
        const step = 40
        if (e.key === "ArrowUp") panRef.y += step
        else if (e.key === "ArrowDown") panRef.y -= step
        else if (e.key === "ArrowLeft") panRef.x += step
        else if (e.key === "ArrowRight") panRef.x -= step
        else return
        e.preventDefault()
        applyTransform(panRef.x, panRef.y, scaleRef.v)
      }}
    >
      {/* Texto para lectores de pantalla */}
      <p class="topo-sr-only" aria-live="polite">
        {hostCount()} dispositivos en la red. Usa doble clic para recentrar la vista.
      </p>

      {/* ── Stage — todo el canvas vive aquí, recibe el transform ──────── */}
      <div
        ref={stageRef}
        class="topo-stage"
        style={{ width: `${CW}px`, height: `${CH}px` }}
      >
        {/* Dispositivos (Modo Dual: SVG+HTML < 500 nodos vs HTML5 2D Canvas > 500 nodos) */}
        <Show
          when={devices().length > 500}
          fallback={
            <>
              {/* SVG: aristas Bézier */}
              <svg class="topo-edges" aria-hidden="true">
                <For each={devices()}>
                  {(d, i) => {
                    const pos  = positions()[i()];
                    const vuln = isVulnerable(d, riskyPorts());
                    const side0: "left" | "right" = pos.x > GX ? "right" : "left";
                    const side1: "left" | "right" = pos.x > GX ? "left" : "right";
                    const x0 = side0 === "right" ? GX + 130 : GX - 130;
                    const x1 = side1 === "left"  ? pos.x - 130 : pos.x + 130;
                    const path = bezierPath(x0, GY, x1, pos.y, side0, side1);
                    return (
                      <path
                        d={path}
                        class={`topo-edge topo-edge-animated${vuln ? " is-risky" : ""}`}
                      />
                    );
                  }}
                </For>
              </svg>

              {/* Gateway / nodo central */}
              <div
                class="topo-node is-gateway"
                style={{ left: `${GX}px`, top: `${GY}px` }}
                role="article"
                aria-label={gateway() ? `Gateway ${gateway()!.ip}` : "Segmento de red local"}
              >
                <div class="topo-node-head">
                  <div class="topo-node-icon" aria-hidden="true">
                    <Icon name="server" class="w-4 h-4" />
                  </div>
                  <div class="topo-node-info">
                    <div class="topo-node-name">
                      {gateway()?.hostname || gateway()?.vendor || (gateway() ? "Gateway" : "Red Local")}
                    </div>
                    <Show when={gateway()?.ip}>
                      <div class="topo-node-ip">{gateway()!.ip}</div>
                    </Show>
                  </div>
                  <span class="topo-node-badge">GW</span>
                </div>
                <div class="topo-node-body">
                  <Show
                    when={gateway()?.openPorts && gateway()!.openPorts!.length > 0}
                    fallback={<span class="topo-port-chip">{gateway()?.vendor || "Gateway"}</span>}
                  >
                    <For each={gateway()!.openPorts}>
                      {(port) => (
                        <span class={`topo-port-chip${riskyPorts().has(port) ? " is-risky" : ""}`}>{port}</span>
                      )}
                    </For>
                  </Show>
                </div>
              </div>

              {/* Dispositivos HTML */}
              <For each={devices()}>
                {(d, i) => {
                  const pos  = positions()[i()];
                  const vuln = isVulnerable(d, riskyPorts());
                  const name = d.hostname || d.vendor || "Dispositivo";
                  const label = `${name} — ${d.ip}${vuln ? " — Alerta de riesgo" : ""}`;
                  return (
                    <div
                      class={`topo-node${vuln ? " is-risky" : ""}`}
                      style={{ left: `${pos.x}px`, top: `${pos.y}px` }}
                      role="article"
                      aria-label={label}
                    >
                      <div class="topo-node-head">
                        <div class="topo-node-icon" aria-hidden="true">
                          <Icon name="terminal" class="w-4 h-4" />
                        </div>
                        <div class="topo-node-info">
                          <div class="topo-node-name" title={name}>{name}</div>
                          <div class="topo-node-ip">{d.ip}</div>
                        </div>
                        {vuln && (
                          <span class="topo-node-badge" aria-label={language.t("topology.canvas.riskDetected")}>
                            {language.t("topology.canvas.risk")}
                          </span>
                        )}
                      </div>

                      <div class="topo-node-body">
                        <span class="topo-node-ports-label">{language.t("topology.canvas.ports")}</span>
                        {d.openPorts && d.openPorts.length > 0 ? (
                          <For each={d.openPorts}>
                            {(port) => (
                              <span
                                class={`topo-port-chip${riskyPorts().has(port) ? " is-risky" : ""}`}
                                aria-label={
                                  riskyPorts().has(port)
                                    ? language.t("topology.canvas.portRisky", { port })
                                    : language.t("topology.canvas.port", { port })
                                }
                              >
                                {port}
                              </span>
                            )}
                          </For>
                        ) : (
                          <span class="topo-no-ports">{language.t("topology.canvas.noPortsDetected")}</span>
                        )}
                      </div>
                    </div>
                  );
                }}
              </For>
            </>
          }
        >
          {/* HTML5 2D Canvas High-Density Renderer (>500 nodos) */}
          <canvas
            ref={(canvasEl) => {
              onMount(() => {
                const ctx = canvasEl.getContext("2d");
                if (!ctx) return;
                canvasEl.width = CW;
                canvasEl.height = CH;

                createEffect(() => {
                  ctx.clearRect(0, 0, CW, CH);
                  const devs = devices();
                  const poss = positions();
                  const colors = resolveCanvasColors();

                  // Draw connections
                  ctx.lineWidth = 1;
                  for (let i = 0; i < devs.length; i++) {
                    const pos = poss[i];
                    if (!pos) continue;
                    const vuln = isVulnerable(devs[i], riskyPorts());
                    ctx.strokeStyle = vuln ? colors.edgeRisky : colors.edge;
                    ctx.globalAlpha = vuln ? 0.6 : 0.45;
                    ctx.beginPath();
                    ctx.moveTo(GX, GY);
                    ctx.lineTo(pos.x, pos.y);
                    ctx.stroke();
                  }
                  ctx.globalAlpha = 1;

                  // Draw central Gateway
                  ctx.fillStyle = colors.gatewayFill;
                  ctx.strokeStyle = colors.gatewayStroke;
                  ctx.lineWidth = 2;
                  ctx.beginPath();
                  ctx.arc(GX, GY, 24, 0, Math.PI * 2);
                  ctx.fill();
                  ctx.stroke();

                  // Draw Device Nodes
                  for (let i = 0; i < devs.length; i++) {
                    const pos = poss[i];
                    if (!pos) continue;
                    const vuln = isVulnerable(devs[i], riskyPorts());
                    ctx.fillStyle = vuln ? colors.nodeRisky : colors.node;
                    ctx.beginPath();
                    ctx.arc(pos.x, pos.y, 8, 0, Math.PI * 2);
                    ctx.fill();
                  }
                });
              });
            }}
            class="absolute inset-0 w-full h-full pointer-events-none"
          />
        </Show>
      </div>

      {/* ── Estado vacío: aún no hay resultados de escaneo ─────────────── */}
      <Show when={isEmpty()}>
        <div class="topo-empty" role="status" aria-live="polite">
          <div class="topo-empty-icon" aria-hidden="true">
            <Icon name="server" class="w-6 h-6" />
          </div>
          <div class="topo-empty-title">{language.t("topology.canvas.empty.title")}</div>
          <div class="topo-empty-sub">
            {language.t("topology.canvas.empty.hintPrefix")} <code>host_discovery</code>{" "}
            {language.t("topology.canvas.empty.hintAnd")} <code>build_topology</code>.{" "}
            {language.t("topology.canvas.empty.hintSuffix")}
          </div>
        </div>
      </Show>

      {/* ── HUD flotante (fuera del stage, no se transforma) ───────────── */}
      <aside class="topo-hud" aria-label={language.t("topology.canvas.hud.ariaLabel")}>
        <h2 class="topo-hud-title">{language.t("topology.canvas.hud.title")}</h2>
        <p class="topo-hud-sub">{language.t("topology.canvas.hud.subtitle")}</p>
        <div class="topo-hud-divider" aria-hidden="true" />
        <div class="topo-hud-status">
          <span class="topo-hud-dot is-live" aria-hidden="true" />
          <span class="topo-hud-count">
            {language.t(hostCount() === 1 ? "topology.canvas.hud.hostsActive.one" : "topology.canvas.hud.hostsActive.other", { count: hostCount() })}
          </span>
        </div>
      </aside>

      {/* ── Controles de zoom (accesibles por teclado) ─────────────────── */}
      <div
        class="topo-zoom-controls"
        role="group"
        aria-label={language.t("topology.canvas.zoom.controlsAriaLabel")}
      >
        <button
          type="button"
          class="topo-zoom-btn"
          aria-label={language.t("topology.canvas.zoom.out")}
          onClick={() => {
            const newS = Math.max(0.1, scaleRef.v - 0.1);
            const w = shellRef.clientWidth, h = shellRef.clientHeight;
            const cx = w / 2, cy = h / 2;
            const px = cx - (newS / scaleRef.v) * (cx - panRef.x);
            const py = cy - (newS / scaleRef.v) * (cy - panRef.y);
            panRef.x = px; panRef.y = py; scaleRef.v = newS;
            applyTransform(px, py, newS);
            setScale(newS);
          }}
        >
          −
        </button>
        <span class="topo-zoom-pct" aria-live="polite" aria-atomic="true">
          {Math.round(scale() * 100)}%
        </span>
        <button
          type="button"
          class="topo-zoom-btn"
          aria-label={language.t("topology.canvas.zoom.in")}
          onClick={() => {
            const newS = Math.min(5, scaleRef.v + 0.1);
            const w = shellRef.clientWidth, h = shellRef.clientHeight;
            const cx = w / 2, cy = h / 2;
            const px = cx - (newS / scaleRef.v) * (cx - panRef.x);
            const py = cy - (newS / scaleRef.v) * (cy - panRef.y);
            panRef.x = px; panRef.y = py; scaleRef.v = newS;
            applyTransform(px, py, newS);
            setScale(newS);
          }}
        >
          +
        </button>
        <button
          type="button"
          class="topo-zoom-btn"
          aria-label={language.t("topology.canvas.zoom.recenter")}
          title={language.t("topology.canvas.zoom.recenterHint")}
          onClick={centerFit}
          style={{ "font-size": "0.5625rem", "font-weight": "700", "letter-spacing": "0.04em", "text-transform": "uppercase", "width": "auto", "padding": "0 0.5rem" }}
        >
          {language.t("topology.canvas.zoom.fit")}
        </button>
      </div>
    </div>
  );
}



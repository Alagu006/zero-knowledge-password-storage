import React, { useState } from "react";
import { Link } from "react-router-dom";
import "../anime-errors.css";

interface Error5xxProps {
  code?: 500 | 502 | 503 | 504;
  title?: string;
  message?: string;
  error?: Error | null;
}

const ERROR_DETAILS: Record<number, { title: string; desc: string; badge: string; sector: string }> = {
  500: {
    title: "CORE MATRIX RUNTIME FAULT",
    desc: "A catastrophic unhandled exception tripped the server circuit breakers. Cyber engineers have been dispatched to contain the plasma leak.",
    badge: "ERR_500 // SYSTEM_OVERLOAD",
    sector: "MAINFRAME://REACTOR-CORE-09",
  },
  502: {
    title: "NEURAL GATEWAY DESYNCHRONIZED",
    desc: "The edge proxy received an invalid cipher handshake from upstream cloud shards. Transmission link severed temporarily.",
    badge: "ERR_502 // BAD_GATEWAY",
    sector: "PROXY://RENDER-ORBITAL-EDGE",
  },
  503: {
    title: "REACTOR OFFLINE FOR CALIBRATION",
    desc: "The cluster node is undergoing high-priority security updates or experiencing abnormal traffic surge. Please hold your fire.",
    badge: "ERR_503 // SERVICE_UNAVAILABLE",
    sector: "SUBSTATION://MAINTENANCE-BAY",
  },
  504: {
    title: "CHRONO-RELAY TIMEOUT",
    desc: "The upstream zero-knowledge encryption node did not respond within the target epoch quantum window.",
    badge: "ERR_504 // TIMEOUT_EXCEEDED",
    sector: "QUANTUM://RELAY-LATENCY",
  },
};

export const Error5xxPage: React.FC<Error5xxProps> = ({
  code = 500,
  title,
  message,
  error,
}) => {
  const [pingStatus, setPingStatus] = useState<string | null>(null);
  const [isPinging, setIsPinging] = useState(false);

  const details = ERROR_DETAILS[code] || ERROR_DETAILS[500];
  const displayTitle = title || details.title;
  const displayDesc = message || details.desc;

  const handlePingNode = async () => {
    setIsPinging(true);
    setPingStatus("TRANSMITTING PING PACKET...");
    const start = performance.now();
    try {
      const res = await fetch("/health", { method: "GET" });
      const elapsed = Math.round(performance.now() - start);
      if (res.ok) {
        setPingStatus(`CORE RESPONDING (${res.status} OK // ${elapsed}ms)`);
      } else {
        setPingStatus(`CORE WARNING (${res.status} ERR // ${elapsed}ms)`);
      }
    } catch {
      const elapsed = Math.round(performance.now() - start);
      setPingStatus(`NODE UNREACHABLE (TIMEOUT // ${elapsed}ms)`);
    } finally {
      setIsPinging(false);
    }
  };

  return (
    <div className="anime-container anime-container-500">
      <div className="anime-card anime-card-500">
        {/* Anime Art Column */}
        <div className="anime-image-wrapper">
          <img
            src="/images/anime-500.jpg"
            alt="Cyberpunk 500 Server Overload Anime Illustration"
            className="anime-image"
          />
          <div className="anime-scanline anime-scanline-500" />
        </div>

        {/* Informational Column */}
        <div>
          <div className="anime-badge anime-badge-500">
            <span className="anime-status-dot" />
            <span>{details.badge}</span>
          </div>

          <h1 className="anime-code anime-code-500">{code}</h1>
          <h2 className="anime-title">{displayTitle}</h2>
          <p className="anime-description">{displayDesc}</p>

          {/* HUD Diagnostics */}
          <div className="anime-hud-box anime-hud-box-500">
            <div className="anime-hud-item">
              <span>CORE LOCATION:</span>
              <span className="anime-hud-highlight anime-hud-highlight-500">{details.sector}</span>
            </div>
            <div className="anime-hud-item">
              <span>DIAGNOSTIC PROBE:</span>
              <span className="anime-hud-highlight anime-hud-highlight-500">
                {pingStatus || "STANDBY (PRESS PING)"}
              </span>
            </div>
            {error && (
              <div className="anime-hud-item">
                <span>STACK TRACE:</span>
                <span style={{ color: "#ff8888", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {error.message}
                </span>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="anime-actions">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="anime-btn-primary anime-btn-primary-500"
            >
              <span>⚡ Reboot Terminal</span>
            </button>

            <button
              type="button"
              onClick={handlePingNode}
              disabled={isPinging}
              className="anime-btn-secondary"
            >
              <span>{isPinging ? "📡 Pinging..." : "📡 Ping Core"}</span>
            </button>

            <Link to="/login" className="anime-btn-secondary">
              <span>🚪 Return to Login</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

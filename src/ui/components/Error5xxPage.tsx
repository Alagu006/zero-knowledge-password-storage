import React, { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import "../anime-errors.css";

interface Error5xxProps {
  code?: number;
  title?: string;
  message?: string;
  error?: Error | null;
}

const ERROR_5XX_DETAILS: Record<number, { title: string; desc: string; badge: string; sector: string }> = {
  500: {
    title: "CORE MATRIX RUNTIME FAULT",
    desc: "A catastrophic unhandled exception tripped the server circuit breakers. Cyber engineers have been dispatched to contain the plasma leak.",
    badge: "ERR_500 // SYSTEM_OVERLOAD",
    sector: "MAINFRAME://REACTOR-CORE-09",
  },
  501: {
    title: "PROTOCOL UNIMPLEMENTED",
    desc: "The server node does not possess the algorithmic capability to fulfill the requested zero-knowledge protocol.",
    badge: "ERR_501 // NOT_IMPLEMENTED",
    sector: "COMPUTE://FUTURE-ENCLAVE",
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
  505: {
    title: "HTTP PROTOCOL VERSION REJECTED",
    desc: "The server node does not support the HTTP protocol major version utilized in the client transmission stream.",
    badge: "ERR_505 // HTTP_VERSION_NOT_SUPPORTED",
    sector: "GATEWAY://PROTOCOL-NEGOTIATOR",
  },
  506: {
    title: "VARIANT NEGOTIATION LOOP",
    desc: "Internal configuration error: the chosen variant resource is configured to engage in transparent content negotiation itself.",
    badge: "ERR_506 // VARIANT_NEGOTIATES",
    sector: "CACHE://CIRCULAR-VARIANT",
  },
  507: {
    title: "CRYPTO SHARD QUOTA DEPLETED",
    desc: "The distributed storage backend is unable to allocate sufficient disk blocks to commit the encrypted vault transaction.",
    badge: "ERR_507 // INSUFFICIENT_STORAGE",
    sector: "DATABASE://SHARD-FULL",
  },
  508: {
    title: "INFINITE RECURSION TRIPPED",
    desc: "The server terminated the execution thread because it detected an infinite redirection or circular dependency loop.",
    badge: "ERR_508 // LOOP_DETECTED",
    sector: "ROUTER://CIRCULAR-DEPENDENCY",
  },
  510: {
    title: "PROTOCOL EXTENSION REQUIRED",
    desc: "Further extensions to the zero-trust request framework are required for the server to fulfill this directive.",
    badge: "ERR_510 // NOT_EXTENDED",
    sector: "ENCLAVE://EXTENSION-ABSENT",
  },
  511: {
    title: "NETWORK AUTHENTICATION INTERCEPT",
    desc: "The client needs to authenticate with the network perimeter before granting internet gateway routing.",
    badge: "ERR_511 // NETWORK_AUTH_REQUIRED",
    sector: "CAPTIVE://PERIMETER-GATEWAY",
  },
};

export const Error5xxPage: React.FC<Error5xxProps> = ({
  code: propCode,
  title,
  message,
  error,
}) => {
  const [pingStatus, setPingStatus] = useState<string | null>(null);
  const [isPinging, setIsPinging] = useState(false);
  const params = useParams<{ code?: string }>();
  const [searchParams] = useSearchParams();

  // Resolve code dynamically: prop -> URL param (:code) -> query string (?code=) -> fallback 500
  const parsedParamCode = params.code ? parseInt(params.code, 10) : undefined;
  const parsedQueryCode = searchParams.get("code") ? parseInt(searchParams.get("code")!, 10) : undefined;
  const activeCode = propCode || parsedParamCode || parsedQueryCode || 500;

  const details = ERROR_5XX_DETAILS[activeCode] || {
    title: `SERVER CRITICAL ANOMALY (${activeCode})`,
    desc: `The server node tripped an unhandled internal exception (${activeCode}). Safe isolation activated to prevent data compromise.`,
    badge: `ERR_${activeCode} // SERVER_ANOMALY`,
    sector: `MAINFRAME://ANOMALY-ISOLATION`,
  };

  const displayTitle = title || searchParams.get("title") || details.title;
  const displayDesc = message || searchParams.get("message") || details.desc;

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
            alt="Cyberpunk 5xx Server Overload Anime Illustration"
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

          <h1 className="anime-code anime-code-500">{activeCode}</h1>
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

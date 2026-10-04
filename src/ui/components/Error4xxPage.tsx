import React from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import "../anime-errors.css";

interface Error4xxProps {
  code?: 400 | 401 | 403 | 404;
  title?: string;
  message?: string;
}

const ERROR_DETAILS: Record<number, { title: string; desc: string; badge: string; sector: string }> = {
  400: {
    title: "CORRUPTED QUANTUM PACKET",
    desc: "The neural node received an illegible or malformed request payload. The zero-trust gateway rejected the cipher frame.",
    badge: "ERR_400 // BAD_REQUEST",
    sector: "SECTOR://DECRYPT-FAIL",
  },
  401: {
    title: "UNAUTHORIZED CIPHER CLEARANCE",
    desc: "Your cryptographic credentials or session token are missing or have expired. Re-authentication is required to access the vault node.",
    badge: "ERR_401 // AUTH_REQUIRED",
    sector: "SECTOR://GATEWAY-GATE-01",
  },
  403: {
    title: "SECURITY PROTOCOL VIOLATION",
    desc: "Access denied by Zero-Trust policy. Your identity lacks permission clearance for this encrypted terminal node.",
    badge: "ERR_403 // FORBIDDEN_ZONE",
    sector: "SECTOR://BLACK-ICE-RESTRICTED",
  },
  404: {
    title: "CYBERSPACE PATH NOT FOUND",
    desc: "The digital coordinate you entered vanished into the dark fiber void or never existed. Check your vector and try again, operative.",
    badge: "ERR_404 // NODE_NOT_FOUND",
    sector: "SECTOR://VOID-MATRIX-NULL",
  },
};

export const Error4xxPage: React.FC<Error4xxProps> = ({ code = 404, title, message }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { token } = useAuth();

  const details = ERROR_DETAILS[code] || ERROR_DETAILS[404];
  const displayTitle = title || details.title;
  const displayDesc = message || details.desc;

  return (
    <div className="anime-container">
      <div className="anime-card">
        {/* Anime Art Column */}
        <div className="anime-image-wrapper">
          <img
            src="/images/anime-404.jpg"
            alt="Cyberpunk 404 Anime Illustration"
            className="anime-image"
          />
          <div className="anime-scanline" />
        </div>

        {/* Informational Column */}
        <div>
          <div className="anime-badge">
            <span className="anime-status-dot" />
            <span>{details.badge}</span>
          </div>

          <h1 className="anime-code">{code}</h1>
          <h2 className="anime-title">{displayTitle}</h2>
          <p className="anime-description">{displayDesc}</p>

          {/* HUD Diagnostics */}
          <div className="anime-hud-box">
            <div className="anime-hud-item">
              <span>TARGET VECTOR:</span>
              <span className="anime-hud-highlight">{location.pathname}</span>
            </div>
            <div className="anime-hud-item">
              <span>SECTOR NODE:</span>
              <span>{details.sector}</span>
            </div>
            <div className="anime-hud-item">
              <span>CRYPTO STATUS:</span>
              <span className="anime-hud-highlight">ZERO-KNOWLEDGE SHIELD ACTIVE</span>
            </div>
          </div>

          {/* Actions */}
          <div className="anime-actions">
            {token ? (
              <Link to="/vault" className="anime-btn-primary">
                <span>🛡️ Return to Vault</span>
              </Link>
            ) : (
              <Link to="/login" className="anime-btn-primary">
                <span>🔑 Log In to Node</span>
              </Link>
            )}

            <button
              type="button"
              onClick={() => {
                if (window.history.length > 1) {
                  navigate(-1);
                } else {
                  navigate("/vault");
                }
              }}
              className="anime-btn-secondary"
            >
              <span>↩ Step Back</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

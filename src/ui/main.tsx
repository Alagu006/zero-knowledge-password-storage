import "./utils/consoleGuard";
import { configureArgon2Mode } from "../crypto/index.js";
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";

// Configure Argon2id parameters before any crypto operations.
// Vite sets import.meta.env.MODE to "production" for build, "development" for dev.
configureArgon2Mode(import.meta.env.MODE === "production" ? "production" : "test");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);

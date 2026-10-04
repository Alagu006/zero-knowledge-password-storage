#!/usr/bin/env node

/**
 * Script to ping Render web service to prevent cold-starts.
 * Can be run standalone or via cron.
 *
 * Usage:
 *   node scripts/keep-alive.js [url]
 */

const targetUrl = process.argv[2] || process.env.RENDER_APP_URL || "https://zero-knowledge-password-storage.onrender.com";
const cleanBaseUrl = targetUrl.replace(/\/+$/, "");

async function ping() {
  console.log(`[${new Date().toISOString()}] Pinging ${cleanBaseUrl}...`);

  for (const endpoint of ["/health", "/"]) {
    const url = `${cleanBaseUrl}${endpoint}`;
    const start = Date.now();
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(60000) });
      const duration = Date.now() - start;
      console.log(`  -> ${endpoint} returned HTTP ${res.status} in ${duration}ms`);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.error(`  -> Failed to ping ${url}: ${errorMsg}`);
    }
  }
}

ping();

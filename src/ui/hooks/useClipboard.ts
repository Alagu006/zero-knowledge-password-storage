import React, { useCallback, useRef, useState } from "react";

const CLIPBOARD_CLEAR_MS = 30_000; // 30 seconds

type UseClipboardReturn = {
  copyToClipboard: (text: string) => Promise<boolean>;
  clearClipboard: () => void;
  copied: boolean;
};

/**
 * Clipboard hook with auto-clear after 30 seconds.
 *
 * SECURITY: Decrypted plaintext copied to the clipboard is automatically
 * cleared after 30 seconds to minimize exposure window. The user is warned
 * about this behavior before copying.
 */
export function useClipboard(): UseClipboardReturn {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [copied, setCopied] = useState(false);

  const clearClipboard = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    navigator.clipboard.writeText("").catch(() => {});
    setCopied(false);
  }, []);

  const copyToClipboard = useCallback(
    async (text: string): Promise<boolean> => {
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);

        if (timerRef.current) clearTimeout(timerRef.current);
        timerRef.current = setTimeout(() => {
          clearClipboard();
        }, CLIPBOARD_CLEAR_MS);

        return true;
      } catch {
        return false;
      }
    },
    [clearClipboard],
  );

  return { copyToClipboard, clearClipboard, copied };
}

"use client";

import { ReactNode, useCallback, useMemo } from "react";
import { AuthProvider } from "../react/client.js";
import { AuthClient } from "../react/clientType.js";
import { invalidateCache } from "./server/invalidateCache.js";
import { ConvexError } from "convex/values";

export function ConvexAuthNextjsClientProvider({
  apiRoute,
  serverState,
  storage,
  storageNamespace,
  shouldHandleCode,
  verbose,
  children,
}: {
  apiRoute?: string;
  serverState: ConvexAuthServerState;
  storage?: "localStorage" | "inMemory";
  storageNamespace?: string;
  verbose?: boolean;
  shouldHandleCode?: () => boolean;
  children: ReactNode;
}) {
  const call: AuthClient["authenticatedCall"] = useCallback(
    async (action, args) => {
      const params = { action, args };
      const response = await fetch(apiRoute ?? "/api/auth", {
        body: JSON.stringify(params),
        method: "POST",
      });
      // Match error handling of Convex Actions
      if (response.status >= 400) {
        const responseJson = await response.json();
        if (responseJson.errorData != undefined) {
          throw new ConvexError(responseJson.errorData);
        }
        throw new Error(responseJson.error);
      }
      return await response.json();
    },
    [apiRoute],
  );
  const authClient = useMemo(
    () => ({
      authenticatedCall: call,
      unauthenticatedCall: call,
      verbose,
    }),
    [call, verbose],
  );
  return (
    <AuthProvider
      client={authClient}
      serverState={serverState}
      onChange={invalidateCache}
      storage={
        // Handle SSR, Client, etc.
        // Pretend we always have storage, the component checks
        // it in first useEffect.
        (typeof window === "undefined"
          ? undefined
          : storage === "inMemory"
            ? null
            : window.localStorage)!
      }
      storageNamespace={
        storageNamespace ??
        requireEnv(process.env.NEXT_PUBLIC_CONVEX_URL, "NEXT_PUBLIC_CONVEX_URL")
      }
      replaceURL={
        // Not used, since the redirect is handled by the Next.js server.
        (url) => {
          window.history.replaceState({}, "", url);
        }
      }
      shouldHandleCode={shouldHandleCode}
    >
      {children}
    </AuthProvider>
  );
}

function requireEnv(value: string | undefined, name: string) {
  if (value === undefined) {
    throw new Error(`Missing environment variable \`${name}\``);
  }
  return value;
}

export type ConvexAuthServerState = {
  _state: { token: string | null; refreshToken: string | null };
  _timeFetched: number;
};

import "server-only";

import { fetchAction } from "convex/nextjs";
import { NextRequest, NextResponse } from "next/server";
import { SignInAction } from "../../server/implementation/index.js";
import { getRequestCookies, getResponseCookies } from "./cookies.js";
import {
  getConvexNextjsOptions,
  getRedactedMessage,
  isCorsRequest,
  jsonResponse,
  logVerbose,
  setAuthCookies,
} from "./utils.js";
import { ConvexError } from "convex/values";

export async function proxyAuthActionToConvex(
  request: NextRequest,
  options: {
    convexUrl?: string;
    verbose?: boolean;
    cookieConfig?: { maxAge: number | null };
  },
) {
  const cookieConfig = options?.cookieConfig ?? { maxAge: null };
  const verbose = options?.verbose ?? false;
  if (request.method !== "POST") {
    return new Response("Invalid method", { status: 405 });
  }
  if (isCorsRequest(request)) {
    return new Response("Invalid origin", { status: 403 });
  }
  const { action, args } = await request.json();

  if (action !== "auth:signIn" && action !== "auth:signOut") {
    logVerbose(`Invalid action ${action}, returning 400`, verbose);
    return new Response("Invalid action", { status: 400 });
  }
  let token: string | undefined;
  if (action === "auth:signIn" && args.refreshToken !== undefined) {
    // The client has a dummy refreshToken, the real one is only
    // stored in cookies.
    const refreshToken = (await getRequestCookies()).refreshToken;
    if (refreshToken === null) {
      console.error(
        "Convex Auth: Unexpected missing refreshToken cookie during client refresh",
      );
      return new Response(JSON.stringify({ tokens: null }));
    }
    args.refreshToken = refreshToken;
  } else {
    // Make sure the proxy is authenticated if the client is,
    // important for signOut and any other logic working
    // with existing sessions.
    token = (await getRequestCookies()).token ?? undefined;
  }
  logVerbose(
    `Fetching action ${action} with args ${JSON.stringify({
      ...args,
      refreshToken: getRedactedMessage(args?.refreshToken ?? ""),
    })}`,
    verbose,
  );

  if (action === "auth:signIn") {
    args.requestContext = {
      cloudflareRayId: request.headers.get("cf-ray") ?? undefined,
      rawHeaders: {
        "accept-language": request.headers.get("accept-language") ?? undefined,
        "sec-ch-ua": request.headers.get("sec-ch-ua") ?? undefined,
        "sec-ch-ua-mobile": request.headers.get("sec-ch-ua-mobile") ?? undefined,
        "sec-ch-ua-platform": request.headers.get("sec-ch-ua-platform") ?? undefined,
        "user-agent": request.headers.get("user-agent") ?? undefined,
      },
      proto: request.headers.get("x-forwarded-proto") ?? undefined,
      ip: request.headers.get("x-real-ip") ?? undefined,
      country: request.headers.get("x-open-next-country") ?? undefined,
      region: request.headers.get("x-open-next-region") ?? undefined,
      city: request.headers.get("x-open-next-city") ?? undefined,
      latitude: request.headers.get("x-open-next-latitude") ?? undefined,
      longitude: request.headers.get("x-open-next-longitude") ?? undefined,
    }

    args.serverAccessToken = process.env.AUTH_SERVER_ACCESS_TOKEN;

    let result: SignInAction["_returnType"];
    // Do not require auth when refreshing tokens or validating a code since they
    // are steps in the auth flow.
    const fetchActionAuthOptions =
      args.refreshToken !== undefined || args.params?.code !== undefined
        ? {}
        : { token };
    try {
      result = await fetchAction(action, args, {
        ...getConvexNextjsOptions(options),
        ...fetchActionAuthOptions,
      });
    } catch (error) {
      console.error(`Hit error while running \`auth:signIn\`:`);
      console.error(error);
      logVerbose(`Clearing auth cookies`, verbose);
      // Send raw error message to client, just like Convex Action would
      let response: NextResponse;
      if (error instanceof ConvexError) {
        console.error("ConvexError caught in auth proxy:", error);
        // Special case for ConvexError to handle auth errors
        response = jsonResponse({
          "errorMessage": error.message,
          "errorData": error.data,
        }, 400)
      } else {
        response = jsonResponse({ error: (error as Error).message }, 400);
      }
      await setAuthCookies(response, null, cookieConfig);
      return response;
    }
    if (result.redirect !== undefined) {
      const { redirect } = result;
      const response = jsonResponse({ redirect });
      (await getResponseCookies(response, cookieConfig)).verifier =
        result.verifier!;
      logVerbose(`Redirecting to ${redirect}`, verbose);
      return response;
    } else if (result.tokens !== undefined) {
      // The server doesn't share the refresh token with the client
      // for added security - the client has to use the server
      // to refresh the access token via cookies.
      logVerbose(
        result.tokens === null
          ? `No tokens returned, clearing auth cookies`
          : `Setting auth cookies with returned tokens`,
        verbose,
      );
      const response = jsonResponse({
        tokens:
          result.tokens !== null
            ? { token: result.tokens.token, refreshToken: "dummy" }
            : null,
      });
      await setAuthCookies(response, result.tokens, cookieConfig);
      return response;
    }
    return jsonResponse(result);
  } else {
    try {
      await fetchAction(action, args, {
        ...getConvexNextjsOptions(options),
        token,
      });
    } catch (error) {
      console.error(`Hit error while running \`auth:signOut\`:`);
      console.error(error);
    }
    logVerbose(`Clearing auth cookies`, verbose);
    const response = jsonResponse(null);
    await setAuthCookies(response, null, cookieConfig);
    return response;
  }
}

export function shouldProxyAuthAction(request: NextRequest, apiRoute: string) {
  // Handle both with and without trailing slash since this could be configured either way.
  // https://nextjs.org/docs/app/api-reference/next-config-js/trailingSlash
  const requestUrl = new URL(request.url);
  if (apiRoute.endsWith("/")) {
    return (
      requestUrl.pathname === apiRoute ||
      requestUrl.pathname === apiRoute.slice(0, -1)
    );
  } else {
    return (
      requestUrl.pathname === apiRoute || requestUrl.pathname === apiRoute + "/"
    );
  }
}

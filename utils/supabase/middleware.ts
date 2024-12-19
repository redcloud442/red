import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { ensureValidSession } from "../serversideProtection";

export async function updateSession(request: NextRequest) {
  // Check if the session validation has already occurred
  if (request.headers.get("x-session-checked")) {
    return addSecurityHeaders(NextResponse.next());
  }

  let supabaseResponse = NextResponse.next({
    request,
  });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) =>
            request.cookies.set(name, value)
          );
          supabaseResponse = NextResponse.next({
            request,
          });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const result = await ensureValidSession();

  if (!result && user) {
    const response = NextResponse.redirect(new URL("/auth/login", request.url));
    response.headers.set("x-session-checked", "true");
    return addSecurityHeaders(response);
  }

  const publicRoutes = [
    "/auth/login",
    "/auth/register",
    "/api/auth",
    "/api/health",
  ];
  const privateRoutes = [
    "/",
    "/dashboard",
    "/api/auth",
    "/admin",
    "/api/health",
  ];
  const currentPath = request.nextUrl.pathname;

  if (!user) {
    if (publicRoutes.some((route) => currentPath.startsWith(route))) {
      return addSecurityHeaders(NextResponse.next());
    }

    if (privateRoutes.some((route) => currentPath.startsWith(route))) {
      const loginUrl = request.nextUrl.clone();
      loginUrl.pathname = "/auth/login";
      const response = NextResponse.redirect(loginUrl);
      response.headers.set("x-session-checked", "true");
      return addSecurityHeaders(response);
    }
  }

  if (user) {
    if (publicRoutes.some((route) => currentPath.startsWith(route))) {
      const homeUrl = request.nextUrl.clone();
      homeUrl.pathname = "/";
      const response = NextResponse.redirect(homeUrl);
      response.headers.set("x-session-checked", "true");
      return addSecurityHeaders(response);
    }
  }

  supabaseResponse.headers.set("x-session-checked", "true");
  return addSecurityHeaders(supabaseResponse);
}

function addSecurityHeaders(response: NextResponse) {
  response.headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains; preload"
  );
  return response;
}

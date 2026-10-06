import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/lib/auth/supabase-auth';
import { Role } from '@prisma/client';

/**
 * Next.js Edge / Server Middleware for Don's Atelier.
 * Intercepts protected route groups:
 * - /api/admin/* : Enforces authentication + ADMIN role
 * - /api/account/* : Enforces authentication (CUSTOMER or ADMIN)
 *
 * Employs consistent error responses matching the application standard.
 */
export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Protected Admin Path Group
  if (pathname.startsWith('/api/admin')) {
    const session = await getSession(req);
    if (!session) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication token is missing, expired, or invalid',
          },
        },
        { status: 401 }
      );
    }

    if (session.user.role !== Role.ADMIN) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Access denied. Requires role: ADMIN',
          },
        },
        { status: 403 }
      );
    }

    // Set user headers for downstream consumption
    const requestHeaders = new Headers(req.headers);
    requestHeaders.set('x-user-id', session.user.id);
    requestHeaders.set('x-user-role', session.user.role);
    requestHeaders.set('x-user-email', session.user.email);

    const res = NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
    res.headers.set('x-user-id', session.user.id);
    res.headers.set('x-user-role', session.user.role);
    res.headers.set('x-user-email', session.user.email);
    return res;
  }

  // Protected Account Path Group
  if (pathname.startsWith('/api/account')) {
    const session = await getSession(req);
    if (!session) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication token is missing, expired, or invalid',
          },
        },
        { status: 401 }
      );
    }

    // Set user headers for downstream consumption
    const requestHeaders = new Headers(req.headers);
    requestHeaders.set('x-user-id', session.user.id);
    requestHeaders.set('x-user-role', session.user.role);
    requestHeaders.set('x-user-email', session.user.email);

    const res = NextResponse.next({
      request: {
        headers: requestHeaders,
      },
    });
    res.headers.set('x-user-id', session.user.id);
    res.headers.set('x-user-role', session.user.role);
    res.headers.set('x-user-email', session.user.email);
    return res;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/api/admin/:path*', '/api/account/:path*'],
};

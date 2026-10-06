import { describe, it, expect } from 'vitest';
import { NextRequest } from 'next/server';
import { GET, HEAD } from '@/app/api/health/route';

describe('/api/health Route', () => {
  it('returns 200 OK with standardized success response on GET', async () => {
    const req = new NextRequest('http://localhost:3000/api/health');
    const response = await GET(req, {} as never);

    expect(response.status).toBe(200);

    // Verify X-Request-Id header is attached
    const requestIdHeader = response.headers.get('x-request-id');
    expect(requestIdHeader).toBeDefined();
    expect(requestIdHeader?.length).toBeGreaterThan(0);

    const body = await response.json();

    // Verify standardized response contract
    expect(body.success).toBe(true);
    expect(body.meta).toBeDefined();
    expect(body.meta.requestId).toBe(requestIdHeader);
    expect(body.meta.timestamp).toBeDefined();

    // Verify service metadata
    expect(body.data).toMatchObject({
      status: 'ok',
      service: "Don's Atelier API",
      package: 'dons-atelier',
      version: '0.1.0',
    });
    expect(typeof body.data.uptimeSeconds).toBe('number');
  });

  it('preserves client-provided X-Request-Id header if valid', async () => {
    const customId = 'client-trace-id-12345';
    const req = new NextRequest('http://localhost:3000/api/health', {
      headers: {
        'x-request-id': customId,
      },
    });

    const response = await GET(req, {} as never);
    expect(response.status).toBe(200);
    expect(response.headers.get('x-request-id')).toBe(customId);

    const body = await response.json();
    expect(body.meta.requestId).toBe(customId);
  });

  it('returns 200 OK on HEAD request', async () => {
    const req = new NextRequest('http://localhost:3000/api/health', {
      method: 'HEAD',
    });
    const response = await HEAD(req, {} as never);

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.success).toBe(true);
    expect(body.data.status).toBe('ok');
  });
});

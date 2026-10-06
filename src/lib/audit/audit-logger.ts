import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { Prisma } from '@prisma/client';
import { logger } from '@/lib/api/logger';
import { getClientIp } from '@/lib/security/rate-limiter';

export interface AuditLogEventParams {
  actorId?: string | null;
  action: string;
  entity: string;
  entityId: string;
  metadata?: Record<string, unknown> | null;
  ip?: string | null;
  userAgent?: string | null;
  tx?: Prisma.TransactionClient;
}

/**
 * Extracts client IP and User-Agent from NextRequest.
 */
export function extractClientMetadata(req: NextRequest): { ip: string; userAgent: string } {
  const ip = getClientIp(req);
  const userAgent = req.headers.get('user-agent') || 'Unknown User-Agent';

  return { ip, userAgent };
}

/**
 * Centralized audit logging helper for Don's Atelier.
 * Used for:
 * - Auth events (register, login success/failure, logout, password resets)
 * - Role modifications
 * - All admin write operations
 */
export async function logAuditEvent(params: AuditLogEventParams) {
  const { actorId, action, entity, entityId, metadata, ip, userAgent, tx } = params;
  const client = tx || prisma;

  try {
    const record = await client.auditLog.create({
      data: {
        actorId: actorId || null,
        action,
        entity,
        entityId,
        metadata: (metadata ?? Prisma.JsonNull) as Prisma.InputJsonValue,
        ip: ip || null,
        userAgent: userAgent || null,
      },
    });

    return record;
  } catch (err: unknown) {
    logger.error(`Audit logging failed for action ${action} on ${entity}:${entityId}`, {
      actorId,
      action,
      entity,
      entityId,
      error: err,
    });

    // In transactions, rethrow to ensure transactional integrity
    if (tx) {
      throw err;
    }

    return null;
  }
}

/**
 * Convenience helper to log an audit event directly from an incoming NextRequest.
 */
export async function logAuditEventFromRequest(
  req: NextRequest,
  params: Omit<AuditLogEventParams, 'ip' | 'userAgent'>
) {
  const { ip, userAgent } = extractClientMetadata(req);
  return logAuditEvent({
    ...params,
    ip,
    userAgent,
  });
}

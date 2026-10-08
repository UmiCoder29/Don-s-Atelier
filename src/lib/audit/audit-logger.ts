import { NextRequest } from 'next/server';
import { prisma } from '@/lib/db/prisma';
import { Prisma } from '@prisma/client';
import { logger } from '@/lib/api/logger';
import { getClientIp } from '@/lib/security/rate-limiter';
import { Actor } from '@/lib/auth/actor';

export interface AuditLogEventParams {
  actor?: Actor | null;
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
 * Sanitizes free-text audit string values:
 * - Strips ASCII control characters (0x00-0x1F and 0x7F-0x9F)
 * - Caps string length at 500 characters
 */
export function sanitizeAuditString(val: string): string {
  // Strip control characters
  const stripped = val.replace(new RegExp('[\\x00-\\x1f\\x7f-\\x9f]', 'g'), '');
  // Cap at 500 characters
  return stripped.length > 500 ? stripped.slice(0, 500) : stripped;
}

/**
 * Recursively sanitizes metadata object ensuring all string fields adhere to audit hygiene.
 */
export function sanitizeAuditMetadata(
  metadata?: Record<string, unknown> | null,
  actor?: Actor | null
): Record<string, unknown> | null {
  const result: Record<string, unknown> = {};

  if (actor) {
    result.actorKind = actor.kind;
    if (actor.kind === 'USER') {
      result.actorRole = actor.role;
    } else if (actor.kind === 'SYSTEM') {
      result.actorName = actor.name;
    }
  }

  if (metadata) {
    for (const [key, val] of Object.entries(metadata)) {
      if (typeof val === 'string') {
        result[key] = sanitizeAuditString(val);
      } else if (Array.isArray(val)) {
        result[key] = val.map((item) =>
          typeof item === 'string' ? sanitizeAuditString(item) : item
        );
      } else if (val && typeof val === 'object') {
        result[key] = sanitizeAuditMetadata(val as Record<string, unknown>);
      } else {
        result[key] = val;
      }
    }
  }

  return Object.keys(result).length > 0 ? result : null;
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
 * - Order lifecycle state transitions & payment confirmations
 */
export async function logAuditEvent(params: AuditLogEventParams) {
  const { actor, action, entity, entityId, metadata, ip, userAgent, tx } = params;
  const client = tx || prisma;

  let resolvedActorId = params.actorId || null;
  if (actor) {
    if (actor.kind === 'USER') {
      resolvedActorId = actor.id;
    } else if (actor.kind === 'SYSTEM') {
      resolvedActorId = null;
    }
  }

  const cleanMetadata = sanitizeAuditMetadata(metadata, actor);

  try {
    const record = await client.auditLog.create({
      data: {
        actorId: resolvedActorId,
        action,
        entity,
        entityId,
        metadata: (cleanMetadata ?? Prisma.JsonNull) as Prisma.InputJsonValue,
        ip: ip || null,
        userAgent: userAgent || null,
      },
    });

    return record;
  } catch (err: unknown) {
    logger.error(`Audit logging failed for action ${action} on ${entity}:${entityId}`, {
      actorId: resolvedActorId,
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

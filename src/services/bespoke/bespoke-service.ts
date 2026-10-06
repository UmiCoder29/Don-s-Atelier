import { prisma } from '@/lib/db/prisma';
import { CustomOrderStatus, Role } from '@prisma/client';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { NotFoundError, ForbiddenError, BadRequestError } from '@/lib/errors/api-error';
import { generateCustomOrderNumber } from '@/lib/crypto';
import {
  encryptField,
  decryptField,
  encryptMeasurementValue,
  decryptMeasurementValue,
} from '@/lib/crypto/field-encryption';
import { logAuditEvent } from '@/lib/audit/audit-logger';
import {
  CreateCustomOrderInput,
  UpdateCustomOrderInput,
  ListCustomOrdersQuery,
  AddCustomOrderNoteInput,
  WithdrawCustomOrderInput,
} from './types';
import {
  validateCustomOrderStoragePath,
  revalidateAndSanitizeAttachment,
} from './attachment-sanitizer';

/**
 * Service managing bespoke tailoring requests and status lifecycle for Don's Atelier.
 *
 * Security Principles:
 * - Prisma connects with a server role that bypasses RLS, so every service function
 *   must also enforce ownership/role in code via assertOwnerOrAdmin.
 * - Customer requests are strictly isolated to their own records.
 * - Only Master Tailor / ADMIN users can quote prices or set production status.
 * - Measurements and notes are encrypted at rest with field-level AES-256-GCM.
 * - Attachments are validated to ensure they belong exclusively to the requesting user.
 */
export class BespokeService {
  /**
   * Submits a new bespoke custom suit request with optional anatomical measurements
   * and up to 5 reference image attachments.
   */
  async createCustomOrder(user: AuthenticatedUser, input: CreateCustomOrderInput) {
    const orderNumber = generateCustomOrderNumber();

    // 1. Pre-validate foreign attachment IDs if provided
    if (input.attachmentIds && input.attachmentIds.length > 0) {
      const existingAttachments = await prisma.customOrderAttachment.findMany({
        where: { id: { in: input.attachmentIds } },
        include: { customOrder: true },
      });

      for (const attId of input.attachmentIds) {
        const found = existingAttachments.find((a) => a.id === attId);
        if (!found || found.customOrder.profileId !== user.id) {
          throw new ForbiddenError('Attachment does not belong to the authenticated user');
        }
      }
    }

    // 2. Pre-validate storage paths for attachments / reference images
    const rawAttachments: Array<{
      storagePath: string;
      fileName?: string | null;
      mimeType: string;
      size: number;
    }> = [];

    if (input.attachments) {
      for (const att of input.attachments) {
        validateCustomOrderStoragePath(user, att.storagePath);
        const sanitized = await revalidateAndSanitizeAttachment(user, att.storagePath, att.fileName);
        rawAttachments.push(sanitized);
      }
    }

    if (input.referenceImages) {
      for (const img of input.referenceImages) {
        const path = typeof img === 'string' ? img : img.storagePath;
        const name = typeof img === 'object' ? img.fileName : null;
        validateCustomOrderStoragePath(user, path);
        const sanitized = await revalidateAndSanitizeAttachment(user, path, name);
        rawAttachments.push(sanitized);
      }
    }

    if (input.attachmentIds) {
      const existing = await prisma.customOrderAttachment.findMany({
        where: { id: { in: input.attachmentIds } },
      });
      for (const att of existing) {
        rawAttachments.push({
          storagePath: att.storagePath,
          fileName: att.fileName,
          mimeType: att.mimeType,
          size: att.size,
        });
      }
    }

    if (rawAttachments.length > 5) {
      throw new BadRequestError('Cannot attach more than 5 reference images per custom suit request');
    }

    const fabricPref = input.fabricPreference || input.fabricPreferences || null;
    const stylePref = input.stylePreference || input.stylePreferences || null;

    // Encrypt notes at rest
    const encryptedNotes = input.notes ? encryptField(input.notes) : null;

    const customOrder = await prisma.$transaction(
      async (tx) => {
        const order = await tx.customOrder.create({
          data: {
            orderNumber,
            profileId: user.id,
            description: input.description,
            occasion: input.occasion || null,
            budgetRange: input.budgetRange || null,
            fabricPreference: fabricPref,
            stylePreference: stylePref,
            notes: encryptedNotes,
            status: CustomOrderStatus.SUBMITTED,
          },
        });

        // Persist anatomical measurements in Entity-Attribute-Value (EAV) structure
        if (input.measurements) {
          let measurementEntries: Array<{
            customOrderId: string;
            key: string;
            value: string;
            unit: string;
            label?: string | null;
          }> = [];

          if (Array.isArray(input.measurements)) {
            measurementEntries = input.measurements.map((m) => ({
              customOrderId: order.id,
              key: m.key,
              value: encryptMeasurementValue(m.value),
              unit: m.unit,
              label: m.label || null,
            }));
          } else {
            const mObj = input.measurements as Record<string, unknown>;
            const defaultUnit = (typeof mObj.unit === 'string' ? mObj.unit : 'inches');
            measurementEntries = Object.entries(input.measurements)
              .filter(([k, val]) => k !== 'unit' && val !== undefined && val !== null)
              .map(([key, val]) => ({
                customOrderId: order.id,
                key,
                value: encryptMeasurementValue(String(val)),
                unit: key.toLowerCase().includes('cm')
                  ? 'cm'
                  : key.toLowerCase().includes('kg')
                  ? 'kg'
                  : defaultUnit,
                label: null,
              }));
          }

          if (measurementEntries.length > 0) {
            await tx.measurement.createMany({
              data: measurementEntries,
            });
          }
        }

        // Persist validated attachments
        if (rawAttachments.length > 0) {
          await tx.customOrderAttachment.createMany({
            data: rawAttachments.map((att) => ({
              customOrderId: order.id,
              storagePath: att.storagePath,
              fileName: att.fileName,
              mimeType: att.mimeType,
              size: att.size,
            })),
          });
        }

        // Record initial status in history (with encrypted note)
        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId: order.id,
            fromStatus: null,
            toStatus: CustomOrderStatus.SUBMITTED,
            changedBy: user.id,
            note: encryptField('Initial bespoke request submitted by customer'),
          },
        });

        // Log system audit event
        await logAuditEvent({
          tx,
          actorId: user.id,
          action: 'CUSTOM_ORDER_SUBMITTED',
          entity: 'CustomOrder',
          entityId: order.id,
          metadata: {
            orderNumber: order.orderNumber,
            description: input.description,
            attachmentCount: rawAttachments.length,
          },
        });

        return order;
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    return this.getCustomOrderById(user, customOrder.id);
  }

  /**
   * Retrieves a bespoke order by ID, enforcing ownership or ADMIN role in application code.
   * Decrypts measurements, notes, and status history notes before returning.
   */
  async getCustomOrderById(user: AuthenticatedUser, customOrderId: string) {
    const order = await prisma.customOrder.findUnique({
      where: { id: customOrderId },
      include: {
        profile: {
          select: { id: true, name: true, email: true },
        },
        measurements: {
          orderBy: { key: 'asc' },
        },
        statusHistory: {
          orderBy: { timestamp: 'desc' },
        },
        attachments: true,
      },
    });

    if (!order) {
      throw new NotFoundError('Custom suit request');
    }

    assertOwnerOrAdmin(user, order.profileId);

    return {
      ...order,
      notes: order.notes ? decryptField(order.notes) : null,
      measurements: order.measurements.map((m) => ({
        ...m,
        value: decryptMeasurementValue(m.value),
      })),
      statusHistory: order.statusHistory.map((h) => ({
        ...h,
        note: h.note ? decryptField(h.note) : null,
      })),
    };
  }

  /**
   * Lists custom suit requests for authenticated customer (or all requests for ADMIN).
   * Decrypts notes and status history notes on all items.
   */
  async listCustomOrders(user: AuthenticatedUser, query: ListCustomOrdersQuery) {
    const page = query.page || 1;
    const limit = query.limit || 20;
    const skip = (page - 1) * limit;

    const whereClause: {
      profileId?: string;
      status?: CustomOrderStatus;
    } = {};

    // Customers see only their own requests
    if (user.role !== Role.ADMIN) {
      whereClause.profileId = user.id;
    }

    if (query.status) {
      whereClause.status = query.status;
    }

    const [orders, totalCount] = await Promise.all([
      prisma.customOrder.findMany({
        where: whereClause,
        include: {
          profile: {
            select: { id: true, name: true, email: true },
          },
          statusHistory: {
            take: 1,
            orderBy: { timestamp: 'desc' },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.customOrder.count({ where: whereClause }),
    ]);

    const decryptedOrders = orders.map((order) => ({
      ...order,
      notes: order.notes ? decryptField(order.notes) : null,
      statusHistory: order.statusHistory.map((h) => ({
        ...h,
        note: h.note ? decryptField(h.note) : null,
      })),
    }));

    return {
      customOrders: decryptedOrders,
      pagination: {
        page,
        limit,
        totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    };
  }

  /**
   * Adds a customer follow-up message or note to their bespoke custom suit request.
   * Field-level encrypts the note and logs to status history.
   */
  async addNote(user: AuthenticatedUser, customOrderId: string, input: AddCustomOrderNoteInput) {
    const existing = await prisma.customOrder.findUnique({
      where: { id: customOrderId },
    });

    if (!existing) {
      throw new NotFoundError('Custom suit request');
    }

    assertOwnerOrAdmin(user, existing.profileId);

    const noteText = input.note || input.message || '';
    if (!noteText.trim()) {
      throw new BadRequestError('Note or message cannot be empty');
    }

    const currentNotes = existing.notes ? decryptField(existing.notes) : '';
    const updatedNotes = currentNotes
      ? `${currentNotes}\n[${new Date().toISOString()}] ${noteText}`
      : noteText;

    const encryptedCombinedNotes = encryptField(updatedNotes);
    const encryptedHistoryNote = encryptField(noteText);

    await prisma.$transaction(
      async (tx) => {
        await tx.customOrder.update({
          where: { id: customOrderId },
          data: {
            notes: encryptedCombinedNotes,
          },
        });

        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId,
            fromStatus: existing.status,
            toStatus: existing.status,
            changedBy: user.id,
            note: encryptedHistoryNote,
          },
        });

        await logAuditEvent({
          tx,
          actorId: user.id,
          action: 'CUSTOM_ORDER_NOTE_ADDED',
          entity: 'CustomOrder',
          entityId: customOrderId,
          metadata: {
            orderNumber: existing.orderNumber,
          },
        });
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    return this.getCustomOrderById(user, customOrderId);
  }

  /**
   * Allows customer to withdraw their bespoke suit request before it enters production.
   * Transitions status to REJECTED (withdrawn) and records audit trail.
   */
  async withdrawCustomOrder(user: AuthenticatedUser, customOrderId: string, input?: WithdrawCustomOrderInput) {
    const existing = await prisma.customOrder.findUnique({
      where: { id: customOrderId },
    });

    if (!existing) {
      throw new NotFoundError('Custom suit request');
    }

    assertOwnerOrAdmin(user, existing.profileId);

    // Business rule: Once in production, ready, or delivered, customer cannot withdraw
    const immutableStatuses: CustomOrderStatus[] = [
      CustomOrderStatus.IN_PRODUCTION,
      CustomOrderStatus.READY,
      CustomOrderStatus.DELIVERED,
    ];
    if (immutableStatuses.includes(existing.status)) {
      throw new BadRequestError('Cannot withdraw a bespoke order that is already in production or completed');
    }

    if (existing.status === CustomOrderStatus.REJECTED) {
      throw new BadRequestError('Custom order request has already been withdrawn or closed');
    }

    const reason = input?.reason ? `Withdrawn by customer: ${input.reason}` : 'Request withdrawn by customer';
    const encryptedNote = encryptField(reason);

    await prisma.$transaction(
      async (tx) => {
        await tx.customOrder.update({
          where: { id: customOrderId },
          data: {
            status: CustomOrderStatus.REJECTED,
          },
        });

        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId,
            fromStatus: existing.status,
            toStatus: CustomOrderStatus.REJECTED,
            changedBy: user.id,
            note: encryptedNote,
          },
        });

        await logAuditEvent({
          tx,
          actorId: user.id,
          action: 'CUSTOM_ORDER_WITHDRAWN',
          entity: 'CustomOrder',
          entityId: customOrderId,
          metadata: {
            orderNumber: existing.orderNumber,
            previousStatus: existing.status,
            reason: input?.reason || null,
          },
        });
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    return this.getCustomOrderById(user, customOrderId);
  }

  /**
   * Updates a bespoke suit request.
   * - Setting quotedPriceInCents requires ADMIN role.
   * - Customers can accept/reject a quoted price.
   */
  async updateCustomOrder(user: AuthenticatedUser, customOrderId: string, input: UpdateCustomOrderInput) {
    const existing = await prisma.customOrder.findUnique({
      where: { id: customOrderId },
    });

    if (!existing) {
      throw new NotFoundError('Custom suit request');
    }

    assertOwnerOrAdmin(user, existing.profileId);

    // Business rule: Only ADMIN can quote a price
    if (input.quotedPriceInCents !== undefined && user.role !== Role.ADMIN) {
      throw new ForbiddenError('Only atelier administrators and master tailors can quote bespoke prices');
    }

    // Business rule: Customers can only transition to ACCEPTED or REJECTED after QUOTED
    if (user.role !== Role.ADMIN && input.status) {
      const allowedCustomerTransitions: CustomOrderStatus[] = [
        CustomOrderStatus.ACCEPTED,
        CustomOrderStatus.REJECTED,
      ];
      if (!allowedCustomerTransitions.includes(input.status)) {
        throw new ForbiddenError('Customers can only accept or reject a quotation');
      }
      if (existing.status !== CustomOrderStatus.QUOTED) {
        throw new BadRequestError(`Cannot transition to ${input.status} until a formal quotation has been provided`);
      }
    }

    const noteText = input.notes || input.message;
    const encryptedNotes = noteText ? encryptField(noteText) : existing.notes;

    const updated = await prisma.$transaction(
      async (tx) => {
        const nextStatus = input.status || (input.quotedPriceInCents ? CustomOrderStatus.QUOTED : existing.status);

        const order = await tx.customOrder.update({
          where: { id: customOrderId },
          data: {
            quotedPriceInCents:
              input.quotedPriceInCents !== undefined ? input.quotedPriceInCents : existing.quotedPriceInCents,
            status: nextStatus,
            notes: encryptedNotes,
          },
        });

        if (nextStatus !== existing.status || noteText) {
          const historyNote = noteText || `Status transitioned to ${nextStatus}`;
          await tx.customOrderStatusHistory.create({
            data: {
              customOrderId: order.id,
              fromStatus: existing.status,
              toStatus: nextStatus,
              changedBy: user.id,
              note: encryptField(historyNote),
            },
          });
        }

        await logAuditEvent({
          tx,
          actorId: user.id,
          action: 'CUSTOM_ORDER_UPDATED',
          entity: 'CustomOrder',
          entityId: order.id,
          metadata: {
            orderNumber: order.orderNumber,
            fromStatus: existing.status,
            toStatus: nextStatus,
            quotedPriceInCents: order.quotedPriceInCents,
          },
        });

        return order;
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    return this.getCustomOrderById(user, updated.id);
  }

  /**
   * Helper verifying that a storage path strictly matches custom-orders/{user.id}/.
   */
  private validateStoragePathOwnership(user: AuthenticatedUser, storagePath: string) {
    validateCustomOrderStoragePath(user, storagePath);
  }
}

export const bespokeService = new BespokeService();

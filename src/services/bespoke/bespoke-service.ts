import { prisma } from '@/lib/db/prisma';
import { CustomOrderStatus, Role } from '@prisma/client';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { NotFoundError, ForbiddenError, BadRequestError, ConflictError } from '@/lib/errors/api-error';
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
  CustomerEditCustomOrderInput,
  AdminUpdateCustomOrderInput,
  AcceptCustomOrderQuoteInput,
  ListCustomOrdersQuery,
  AddCustomOrderNoteInput,
  WithdrawCustomOrderInput,
} from './types';
import {
  validateCustomOrderStoragePath,
  revalidateAndSanitizeAttachment,
} from './attachment-sanitizer';
import { validateStatusTransition } from './order-state-machine';
import { generateWhatsAppHandoffUrl } from './whatsapp-handoff';
import { notificationService } from '@/services/notifications/notification-service';

/**
 * Service managing bespoke tailoring requests and status lifecycle for Don's Atelier.
 *
 * Security Principles:
 * - Prisma connects with a server role that bypasses RLS, so every service function
 *   must enforce ownership/role in code via assertOwnerOrAdmin.
 * - Customer requests are strictly isolated to their own records (IDOR protection).
 * - Single central state machine enforces all allowed status transitions.
 * - Concurrency protection: Quote acceptance and admin quoting use row locking (FOR UPDATE)
 *   to prevent stale price acceptance race conditions.
 * - Internal notes are encrypted at field level and NEVER leaked to customer endpoints.
 * - History and audit records are written atomically in the same transaction as status changes.
 * - WhatsApp handoff URLs contain only the reference code and fixed greeting (zero PII).
 * - Post-commit notifications are dispatched safely; notification failures never rollback transitions.
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

    // Encrypt customer notes at rest
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
            const defaultUnit = typeof mObj.unit === 'string' ? mObj.unit : 'inches';
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

        // Record initial status in history
        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId: order.id,
            fromStatus: null,
            toStatus: CustomOrderStatus.SUBMITTED,
            changedBy: user.id,
            note: encryptField('Initial bespoke request submitted by customer'),
          },
        });

        // Log system audit event (strictly no customer measurements or notes in metadata)
        await logAuditEvent({
          tx,
          actorId: user.id,
          action: 'CUSTOM_ORDER_SUBMITTED',
          entity: 'CustomOrder',
          entityId: order.id,
          metadata: {
            orderNumber: order.orderNumber,
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

    // Post-commit notification (never fails or rolls back the order creation)
    try {
      await notificationService.sendStatusChangeNotification({
        referenceCode: customOrder.orderNumber,
        newStatus: CustomOrderStatus.SUBMITTED,
      });
    } catch (notifErr) {
      console.warn('[NotificationService] Status notification error on creation:', notifErr);
    }

    return this.getCustomOrderById(user, customOrder.id);
  }

  /**
   * Retrieves a bespoke order by ID, enforcing ownership or ADMIN role in application code.
   *
   * Privacy & Security Guarantees:
   * - Measurements and customer notes are decrypted.
   * - For CUSTOMERS:
   *   - internalNotes are completely stripped/omitted.
   *   - Status history rows tagged with [INTERNAL] have their note sanitized to null.
   * - For ADMINS:
   *   - internalNotes are decrypted and surfaced.
   *   - Full status history with internal notes is viewable.
   * - Includes generated wa.me WhatsApp handoff URL (sanitized, zero PII).
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

    const isAdmin = user.role === Role.ADMIN;
    const whatsappHandoffUrl = generateWhatsAppHandoffUrl(order.orderNumber);

    // Decrypt and process status history
    let latestInternalNote: string | null = null;
    const sanitizedHistory = order.statusHistory.map((h) => {
      const decryptedNote = h.note ? decryptField(h.note) : null;
      const isInternal = Boolean(decryptedNote && decryptedNote.startsWith('[INTERNAL]'));

      if (isInternal && decryptedNote && !latestInternalNote) {
        latestInternalNote = decryptedNote.replace(/^\[INTERNAL\]\s*/, '');
      }

      if (!isAdmin && isInternal) {
        // Strip internal note from customer response (explicitly nulled)
        return {
          id: h.id,
          fromStatus: h.fromStatus,
          toStatus: h.toStatus,
          timestamp: h.timestamp,
          note: null,
        };
      }

      return {
        id: h.id,
        fromStatus: h.fromStatus,
        toStatus: h.toStatus,
        timestamp: h.timestamp,
        note: isInternal && isAdmin && decryptedNote ? decryptedNote.replace(/^\[INTERNAL\]\s*/, '') : decryptedNote,
      };
    });

    if (!isAdmin) {
      // Customer detail response: strictly allowlisted fields only
      return {
        id: order.id,
        orderNumber: order.orderNumber,
        profileId: order.profileId,
        description: order.description,
        occasion: order.occasion ?? null,
        budgetRange: order.budgetRange ?? null,
        fabricPreference: order.fabricPreference ?? null,
        stylePreference: order.stylePreference ?? null,
        status: order.status,
        quotedPriceInCents: order.quotedPriceInCents ?? null,
        notes: order.notes ? decryptField(order.notes) : null,
        measurements: order.measurements.map((m) => ({
          id: m.id,
          key: m.key,
          value: decryptMeasurementValue(m.value),
          unit: m.unit,
          label: m.label ?? null,
        })),
        attachments: order.attachments.map((a) => ({
          id: a.id,
          storagePath: a.storagePath,
          fileName: a.fileName ?? null,
          mimeType: a.mimeType,
          size: a.size,
          createdAt: a.createdAt,
        })),
        statusHistory: sanitizedHistory,
        whatsappHandoffUrl,
        createdAt: order.createdAt,
        updatedAt: order.updatedAt,
      };
    }

    // Admin detail response: includes admin profile, internal notes, and decrypted history
    return {
      id: order.id,
      orderNumber: order.orderNumber,
      profileId: order.profileId,
      profile: order.profile,
      description: order.description,
      occasion: order.occasion ?? null,
      budgetRange: order.budgetRange ?? null,
      fabricPreference: order.fabricPreference ?? null,
      stylePreference: order.stylePreference ?? null,
      status: order.status,
      quotedPriceInCents: order.quotedPriceInCents ?? null,
      notes: order.notes ? decryptField(order.notes) : null,
      internalNotes: latestInternalNote,
      measurements: order.measurements.map((m) => ({
        id: m.id,
        key: m.key,
        value: decryptMeasurementValue(m.value),
        unit: m.unit,
        label: m.label ?? null,
      })),
      attachments: order.attachments.map((a) => ({
        id: a.id,
        storagePath: a.storagePath,
        fileName: a.fileName ?? null,
        mimeType: a.mimeType,
        size: a.size,
        createdAt: a.createdAt,
      })),
      statusHistory: sanitizedHistory,
      whatsappHandoffUrl,
      createdAt: order.createdAt,
      updatedAt: order.updatedAt,
    };
  }

  /**
   * Lists custom suit requests for authenticated customer (or all requests for ADMIN).
   * Supports pagination and filtering by status.
   * Strictly sanitizes internal notes from customer views using explicit allowlist.
   */
  async listCustomOrders(user: AuthenticatedUser, query: ListCustomOrdersQuery) {
    const page = query.page || 1;
    const limit = query.limit || 20;
    const skip = (page - 1) * limit;
    const isAdmin = user.role === Role.ADMIN;

    const whereClause: {
      profileId?: string;
      status?: CustomOrderStatus;
    } = {};

    // Customers see only their own requests
    if (!isAdmin) {
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
            take: 5,
            orderBy: { timestamp: 'desc' },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.customOrder.count({ where: whereClause }),
    ]);

    const decryptedOrders = orders.map((order) => {
      let latestInternalNote: string | null = null;
      const sanitizedHistory = order.statusHistory.map((h) => {
        const decryptedNote = h.note ? decryptField(h.note) : null;
        const isInternal = Boolean(decryptedNote && decryptedNote.startsWith('[INTERNAL]'));

        if (isInternal && decryptedNote && !latestInternalNote) {
          latestInternalNote = decryptedNote.replace(/^\[INTERNAL\]\s*/, '');
        }

        if (!isAdmin && isInternal) {
          return {
            id: h.id,
            fromStatus: h.fromStatus,
            toStatus: h.toStatus,
            timestamp: h.timestamp,
            note: null,
          };
        }

        return {
          id: h.id,
          fromStatus: h.fromStatus,
          toStatus: h.toStatus,
          timestamp: h.timestamp,
          note: isInternal && isAdmin && decryptedNote ? decryptedNote.replace(/^\[INTERNAL\]\s*/, '') : decryptedNote,
        };
      });

      if (!isAdmin) {
        // Customer list response: strictly allowlisted fields only
        return {
          id: order.id,
          orderNumber: order.orderNumber,
          profileId: order.profileId,
          description: order.description,
          occasion: order.occasion ?? null,
          budgetRange: order.budgetRange ?? null,
          fabricPreference: order.fabricPreference ?? null,
          stylePreference: order.stylePreference ?? null,
          status: order.status,
          quotedPriceInCents: order.quotedPriceInCents ?? null,
          notes: order.notes ? decryptField(order.notes) : null,
          statusHistory: sanitizedHistory,
          whatsappHandoffUrl: generateWhatsAppHandoffUrl(order.orderNumber),
          createdAt: order.createdAt,
          updatedAt: order.updatedAt,
        };
      }

      // Admin list response: includes profile and internalNotes
      return {
        id: order.id,
        orderNumber: order.orderNumber,
        profileId: order.profileId,
        profile: order.profile,
        description: order.description,
        occasion: order.occasion ?? null,
        budgetRange: order.budgetRange ?? null,
        fabricPreference: order.fabricPreference ?? null,
        stylePreference: order.stylePreference ?? null,
        status: order.status,
        quotedPriceInCents: order.quotedPriceInCents ?? null,
        notes: order.notes ? decryptField(order.notes) : null,
        internalNotes: latestInternalNote,
        statusHistory: sanitizedHistory,
        whatsappHandoffUrl: generateWhatsAppHandoffUrl(order.orderNumber),
        createdAt: order.createdAt,
        updatedAt: order.updatedAt,
      };
    });

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
   * Dedicated Admin List Route helper with status filtering and pagination.
   * Strictly requires ADMIN role.
   */
  async adminListCustomOrders(adminUser: AuthenticatedUser, query: ListCustomOrdersQuery) {
    if (adminUser.role !== Role.ADMIN) {
      throw new ForbiddenError('Only atelier administrators may access the custom orders management list');
    }
    return this.listCustomOrders(adminUser, query);
  }

  /**
   * Dedicated Admin Status Transition & Quoting Route.
   *
   * Business & Security Rules:
   * - Strictly requires ADMIN role.
   * - Uses row lock (FOR UPDATE) to prevent race conditions.
   * - Setting quotedPriceInCents is only permitted when transitioning to or re-quoting in QUOTED.
   * - Changing quotedPriceInCents while in QUOTED resets/maintains status at QUOTED.
   * - Moving to QUOTED requires a valid quotedPriceInCents (either supplied or already on record).
   * - Internal notes are encrypted with AES-256-GCM and stored in history with [INTERNAL] tag.
   * - Atomic transition: CustomOrder, CustomOrderStatusHistory, and AuditLog all write in one tx.
   * - Post-commit notification dispatched safely.
   */
  async adminUpdateCustomOrder(
    adminUser: AuthenticatedUser,
    customOrderId: string,
    input: AdminUpdateCustomOrderInput
  ) {
    if (adminUser.role !== Role.ADMIN) {
      throw new ForbiddenError('Only atelier administrators may perform administrative updates');
    }

    const finalPrice =
      input.quotedPriceInCents !== undefined ? input.quotedPriceInCents : input.quotedPrice;

    const { updatedOrder, fromStatus, toStatus } = await prisma.$transaction(
      async (tx) => {
        // 1. Acquire row lock on the custom order
        const lockedRows = await tx.$queryRaw<
          Array<{
            id: string;
            status: CustomOrderStatus;
            quotedPriceInCents: number | null;
            orderNumber: string;
            notes: string | null;
          }>
        >`
          SELECT id, status, "quotedPriceInCents", "orderNumber", notes
          FROM custom_orders
          WHERE id = ${customOrderId}
          FOR UPDATE
        `;

        if (lockedRows.length === 0) {
          throw new NotFoundError('Custom suit request');
        }

        const current = lockedRows[0];

        // 2. Determine target status & validate price rules
        let nextStatus: CustomOrderStatus = current.status;

        if (finalPrice !== undefined) {
          // Setting price is only permitted when moving to QUOTED or re-quoting while QUOTED
          if (input.status && input.status !== CustomOrderStatus.QUOTED) {
            throw new BadRequestError(
              'Quoted price can only be specified when setting or updating status to QUOTED'
            );
          }
          if (current.status !== CustomOrderStatus.IN_REVIEW && current.status !== CustomOrderStatus.QUOTED) {
            throw new ConflictError(
              'A price quotation can only be provided when an order is IN_REVIEW or already QUOTED'
            );
          }
          nextStatus = CustomOrderStatus.QUOTED;
        } else if (input.status) {
          nextStatus = input.status;
        }

        // Validate that moving to QUOTED has a valid price
        if (nextStatus === CustomOrderStatus.QUOTED) {
          const effectivePrice = finalPrice !== undefined ? finalPrice : current.quotedPriceInCents;
          if (effectivePrice === null || effectivePrice === undefined) {
            throw new BadRequestError('A positive integer quoted price in cents is required to quote an order');
          }
        }

        // 3. Central State Machine validation
        if (nextStatus !== current.status || (current.status === CustomOrderStatus.QUOTED && finalPrice !== undefined)) {
          validateStatusTransition(current.status, nextStatus, Role.ADMIN);
        }

        // 4. Handle internal notes encryption
        let historyNoteText: string;
        if (input.internalNotes) {
          historyNoteText = `[INTERNAL] ${input.internalNotes}`;
        } else if (input.notes) {
          historyNoteText = input.notes;
        } else if (current.status === CustomOrderStatus.QUOTED && nextStatus === CustomOrderStatus.QUOTED && finalPrice) {
          historyNoteText = `Quotation revised to ${(finalPrice / 100).toFixed(2)} USD by master tailor`;
        } else {
          historyNoteText = `Status transitioned to ${nextStatus} by atelier administration`;
        }

        const encryptedHistoryNote = encryptField(historyNoteText);

        // 5. Update custom order record
        const order = await tx.customOrder.update({
          where: { id: customOrderId },
          data: {
            status: nextStatus,
            quotedPriceInCents: finalPrice !== undefined ? finalPrice : current.quotedPriceInCents,
          },
        });

        // 6. Write status history entry
        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId: order.id,
            fromStatus: current.status,
            toStatus: nextStatus,
            changedBy: adminUser.id,
            note: encryptedHistoryNote,
          },
        });

        // 7. Write system audit log (strictly NO notes, measurements, or phone numbers in metadata)
        await logAuditEvent({
          tx,
          actorId: adminUser.id,
          action: 'CUSTOM_ORDER_STATUS_CHANGED',
          entity: 'CustomOrder',
          entityId: order.id,
          metadata: {
            orderNumber: order.orderNumber,
            fromStatus: current.status,
            toStatus: nextStatus,
            quotedPriceInCents: order.quotedPriceInCents,
          },
        });

        return { updatedOrder: order, fromStatus: current.status, toStatus: nextStatus };
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    // 8. Post-commit notification dispatch (failure never rolls back status change)
    if (fromStatus !== toStatus) {
      try {
        await notificationService.sendStatusChangeNotification({
          referenceCode: updatedOrder.orderNumber,
          newStatus: toStatus,
        });
      } catch (notifErr) {
        console.warn('[NotificationService] Status notification error on admin update:', notifErr);
      }
    }

    return this.getCustomOrderById(adminUser, updatedOrder.id);
  }

  /**
   * Customer Quote Acceptance with Strict Row Locking & Race Safety.
   *
   * Quote Safety Rules:
   * - Enforces row lock (FOR UPDATE).
   * - If admin re-quotes while customer is accepting, customer receives 409 Conflict.
   * - Expected price comparison ensures customer never accepts a stale or revised quote.
   * - Admin users CANNOT accept quotations on behalf of customers (throws 403 Forbidden).
   * - Atomic transition: CustomOrder + CustomOrderStatusHistory + AuditLog in single transaction.
   * - Post-commit notification dispatch.
   */
  async acceptCustomOrderQuote(
    customerUser: AuthenticatedUser,
    customOrderId: string,
    input?: AcceptCustomOrderQuoteInput
  ) {
    // Role check: Admins cannot accept on customer behalf
    if (customerUser.role === Role.ADMIN) {
      throw new ForbiddenError('Administrators cannot accept quotations on behalf of customers');
    }

    const { updatedOrder, fromStatus, toStatus } = await prisma.$transaction(
      async (tx) => {
        // 1. Row lock on the custom order
        const lockedRows = await tx.$queryRaw<
          Array<{
            id: string;
            profileId: string;
            status: CustomOrderStatus;
            quotedPriceInCents: number | null;
            orderNumber: string;
          }>
        >`
          SELECT id, "profileId", status, "quotedPriceInCents", "orderNumber"
          FROM custom_orders
          WHERE id = ${customOrderId}
          FOR UPDATE
        `;

        if (lockedRows.length === 0) {
          throw new NotFoundError('Custom suit request');
        }

        const current = lockedRows[0];

        // 2. Ownership verification (Customer isolation)
        assertOwnerOrAdmin(customerUser, current.profileId);

        // 3. Central state machine check
        validateStatusTransition(current.status, CustomOrderStatus.ACCEPTED, customerUser.role);

        // 4. Quote price safety check
        if (current.quotedPriceInCents === null) {
          throw new ConflictError('Cannot accept custom order without a formal quotation');
        }

        if (
          input?.expectedPriceInCents !== undefined &&
          current.quotedPriceInCents !== input.expectedPriceInCents
        ) {
          throw new ConflictError(
            'The quoted price has changed since you viewed it. Please review the updated quotation before accepting.'
          );
        }

        const historyNote = input?.notes || 'Quotation accepted by customer';

        // 5. Update order to ACCEPTED
        const order = await tx.customOrder.update({
          where: { id: customOrderId },
          data: {
            status: CustomOrderStatus.ACCEPTED,
          },
        });

        // 6. Record status history
        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId: order.id,
            fromStatus: current.status,
            toStatus: CustomOrderStatus.ACCEPTED,
            changedBy: customerUser.id,
            note: encryptField(historyNote),
          },
        });

        // 7. System audit log
        await logAuditEvent({
          tx,
          actorId: customerUser.id,
          action: 'CUSTOM_ORDER_STATUS_CHANGED',
          entity: 'CustomOrder',
          entityId: order.id,
          metadata: {
            orderNumber: order.orderNumber,
            fromStatus: current.status,
            toStatus: CustomOrderStatus.ACCEPTED,
            quotedPriceInCents: current.quotedPriceInCents,
          },
        });

        return { updatedOrder: order, fromStatus: current.status, toStatus: CustomOrderStatus.ACCEPTED };
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    // 8. Post-commit notification
    try {
      await notificationService.sendStatusChangeNotification({
        referenceCode: updatedOrder.orderNumber,
        newStatus: toStatus,
      });
    } catch (notifErr) {
      console.warn('[NotificationService] Status notification error on acceptance:', notifErr);
    }

    return this.getCustomOrderById(customerUser, updatedOrder.id);
  }

  /**
   * Customer Request Withdrawal / Cancellation Lifecycle.
   *
   * Rules:
   * - Transitions to REJECTED (terminal state).
   * - Enforces central state machine (permitted before production).
   * - Row lock (FOR UPDATE).
   * - Atomic transition with history and audit logs.
   */
  async withdrawCustomOrder(
    user: AuthenticatedUser,
    customOrderId: string,
    input?: WithdrawCustomOrderInput
  ) {
    const { updatedOrder, fromStatus, toStatus } = await prisma.$transaction(
      async (tx) => {
        const lockedRows = await tx.$queryRaw<
          Array<{
            id: string;
            profileId: string;
            status: CustomOrderStatus;
            orderNumber: string;
          }>
        >`
          SELECT id, "profileId", status, "orderNumber"
          FROM custom_orders
          WHERE id = ${customOrderId}
          FOR UPDATE
        `;

        if (lockedRows.length === 0) {
          throw new NotFoundError('Custom suit request');
        }

        const current = lockedRows[0];

        // Ownership verification
        assertOwnerOrAdmin(user, current.profileId);

        // Central State Machine validation
        validateStatusTransition(current.status, CustomOrderStatus.REJECTED, user.role);

        const reason = input?.reason
          ? `Withdrawn by customer: ${input.reason}`
          : 'Request withdrawn by customer';

        const order = await tx.customOrder.update({
          where: { id: customOrderId },
          data: {
            status: CustomOrderStatus.REJECTED,
          },
        });

        await tx.customOrderStatusHistory.create({
          data: {
            customOrderId,
            fromStatus: current.status,
            toStatus: CustomOrderStatus.REJECTED,
            changedBy: user.id,
            note: encryptField(reason),
          },
        });

        await logAuditEvent({
          tx,
          actorId: user.id,
          action: 'CUSTOM_ORDER_WITHDRAWN',
          entity: 'CustomOrder',
          entityId: customOrderId,
          metadata: {
            orderNumber: order.orderNumber,
            fromStatus: current.status,
            toStatus: CustomOrderStatus.REJECTED,
          },
        });

        return { updatedOrder: order, fromStatus: current.status, toStatus: CustomOrderStatus.REJECTED };
      },
      {
        maxWait: 30000,
        timeout: 60000,
      }
    );

    try {
      await notificationService.sendStatusChangeNotification({
        referenceCode: updatedOrder.orderNumber,
        newStatus: toStatus,
      });
    } catch (notifErr) {
      console.warn('[NotificationService] Status notification error on withdrawal:', notifErr);
    }

    return this.getCustomOrderById(user, customOrderId);
  }

  /**
   * Customer edits non-status fields (e.g. description, preferences) while order is in SUBMITTED status.
   * Atomically checked and updated under row-level lock (FOR UPDATE) within a transaction.
   * Disallowed for any other status (throws ConflictError 409).
   */
  async customerEditCustomOrder(
    user: AuthenticatedUser,
    customOrderId: string,
    input: CustomerEditCustomOrderInput
  ) {
    const dataToUpdate: {
      description?: string;
      occasion?: string | null;
      budgetRange?: string | null;
      fabricPreference?: string | null;
      stylePreference?: string | null;
    } = {};

    if (input.description !== undefined) dataToUpdate.description = input.description;
    if (input.occasion !== undefined) dataToUpdate.occasion = input.occasion;
    if (input.budgetRange !== undefined) dataToUpdate.budgetRange = input.budgetRange;
    if (input.fabricPreference !== undefined) dataToUpdate.fabricPreference = input.fabricPreference;
    if (input.stylePreference !== undefined) dataToUpdate.stylePreference = input.stylePreference;

    await prisma.$transaction(
      async (tx) => {
        const lockedRows = await tx.$queryRaw<
          Array<{
            id: string;
            profileId: string;
            status: CustomOrderStatus;
          }>
        >`
          SELECT id, "profileId", status
          FROM custom_orders
          WHERE id = ${customOrderId}
          FOR UPDATE
        `;

        if (lockedRows.length === 0) {
          throw new NotFoundError('Custom suit request');
        }

        const current = lockedRows[0];

        // Enforce owner-only: admins must use admin route; non-owners are rejected
        if (user.role === Role.ADMIN || user.id !== current.profileId) {
          throw new ForbiddenError(
            'Customer edit route is reserved strictly for order owners. Administrators must use /api/admin/custom-orders/[id]'
          );
        }

        if (current.status !== CustomOrderStatus.SUBMITTED) {
          throw new ConflictError(
            'Custom suit requests can only be edited while in SUBMITTED status'
          );
        }

        await tx.customOrder.update({
          where: { id: customOrderId },
          data: dataToUpdate,
        });

        // Write audit entry in the same transaction listing changed FIELD NAMES only, no values
        const changedFields = Object.keys(dataToUpdate);
        await tx.auditLog.create({
          data: {
            actorId: user.id,
            action: 'CUSTOM_ORDER_CUSTOMER_EDIT',
            entity: 'CustomOrder',
            entityId: customOrderId,
            metadata: {
              changedFields,
            },
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
   * General Update Custom Order method.
   * Serves as backwards-compatible dispatcher.
   */
  async updateCustomOrder(
    user: AuthenticatedUser,
    customOrderId: string,
    input: UpdateCustomOrderInput
  ) {
    const existing = await prisma.customOrder.findUnique({
      where: { id: customOrderId },
    });

    if (!existing) {
      throw new NotFoundError('Custom suit request');
    }

    assertOwnerOrAdmin(user, existing.profileId);

    // If caller is ADMIN, dispatch to adminUpdateCustomOrder
    if (user.role === Role.ADMIN) {
      return this.adminUpdateCustomOrder(user, customOrderId, {
        status: input.status,
        quotedPriceInCents: input.quotedPriceInCents,
        internalNotes: input.internalNotes,
        notes: input.notes || input.message,
      });
    }

    // Caller is CUSTOMER
    if (input.status === CustomOrderStatus.ACCEPTED) {
      if (input.expectedPriceInCents === undefined) {
        throw new BadRequestError('expectedPriceInCents is required to accept a quotation');
      }
      return this.acceptCustomOrderQuote(user, customOrderId, {
        expectedPriceInCents: input.expectedPriceInCents,
        notes: input.notes || input.message,
      });
    }

    if (input.status === CustomOrderStatus.REJECTED) {
      return this.withdrawCustomOrder(user, customOrderId, {
        reason: input.notes || input.message,
      });
    }

    // Any other status change attempted by customer is rejected by state machine / role rules
    if (input.status) {
      validateStatusTransition(existing.status, input.status, user.role);
    }

    // Customer attempting to quote price is strictly forbidden
    if (input.quotedPriceInCents !== undefined) {
      throw new ForbiddenError('Only atelier administrators and master tailors can quote bespoke prices');
    }

    // If customer just wants to add a note or message without status change
    const noteText = input.notes || input.message;
    if (noteText) {
      return this.addNote(user, customOrderId, { note: noteText });
    }

    return this.getCustomOrderById(user, customOrderId);
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
}

export const bespokeService = new BespokeService();

import { AuthenticatedUser, Role } from '@/lib/auth/supabase-auth';
import { ForbiddenError, UnauthorizedError, NotFoundError } from '@/lib/errors/api-error';
import { STORAGE_BUCKETS, StorageBucket } from './buckets';
import { prisma } from '@/lib/db/prisma';

export type StorageOperation = 'read' | 'write' | 'signed_upload' | 'signed_download';

/**
 * Enforces role-based and ownership-based access control for Don's Atelier storage buckets:
 *
 * 1. 'product-images' (Public Read, Admin Write):
 *    - read: allowed anonymously and for all users.
 *    - write / signed_upload: strictly restricted to users with ADMIN role.
 *
 * 2. 'custom-order-uploads' (Private; Owner + Admin Only via Signed URLs):
 *    - Anonymous access: strictly rejected with 401 Unauthorized.
 *    - ADMIN role: granted full read/write/signed URL access.
 *    - CUSTOMER role: allowed ONLY if the file belongs to the customer:
 *      (a) Path begins with the user's profile ID (`${user.id}/...` or `custom-orders/${user.id}/...`), OR
 *      (b) Path is associated with a CustomOrderAttachment whose CustomOrder belongs to `user.id`.
 *    - Any other customer access: strictly rejected with 403 Forbidden.
 */
export async function assertStorageAccess(options: {
  user: AuthenticatedUser | null;
  bucket: string;
  operation: StorageOperation;
  storagePath?: string;
  customOrderId?: string;
}): Promise<void> {
  const { user, bucket, operation, storagePath, customOrderId } = options;

  // 1. PRODUCT-IMAGES BUCKET
  if (bucket === STORAGE_BUCKETS.PRODUCT_IMAGES) {
    if (operation === 'read') {
      return; // Public read is allowed
    }

    if (!user) {
      throw new UnauthorizedError('Authentication required to upload or manage product images');
    }

    if (user.role !== Role.ADMIN) {
      throw new ForbiddenError(
        'Access denied: Only atelier administrators can upload or manage product showcase images'
      );
    }

    return;
  }

  // 2. CUSTOM-ORDER-UPLOADS (PRIVATE BUCKET)
  if (bucket === STORAGE_BUCKETS.CUSTOM_ORDER_UPLOADS) {
    if (!user) {
      throw new UnauthorizedError(
        'Authentication required to access files in private custom order uploads'
      );
    }

    // Admins have global access to all custom order uploads
    if (user.role === Role.ADMIN) {
      return;
    }

    // Customers must prove ownership of the specific upload or custom order
    if (customOrderId) {
      const order = await prisma.customOrder.findUnique({
        where: { id: customOrderId },
        select: { profileId: true },
      });

      if (!order) {
        throw new NotFoundError('Custom bespoke order');
      }

      if (order.profileId !== user.id) {
        throw new ForbiddenError(
          'Access denied: You do not have permission to access uploads for this bespoke order'
        );
      }

      return;
    }

    if (storagePath) {
      const normalizedPath = storagePath.replace(/^\/+/, '');

      // Check path-based ownership prefix: strictly custom-orders/{userId}/...
      if (normalizedPath.startsWith(`custom-orders/${user.id}/`)) {
        return;
      }

      // Check database attachment linkage
      const attachment = await prisma.customOrderAttachment.findFirst({
        where: { storagePath },
        include: {
          customOrder: {
            select: { profileId: true },
          },
        },
      });

      if (attachment) {
        if (attachment.customOrder.profileId === user.id) {
          return;
        }

        throw new ForbiddenError(
          'Access denied: You do not have permission to access this private custom order upload'
        );
      }

      // Path does not match user prefix and is not linked to their order
      throw new ForbiddenError(
        'Access denied: You do not have permission to access this private upload'
      );
    }

    // Customer attempting generic or unspecified access to private bucket
    throw new ForbiddenError(
      'Access denied: You do not have permission to access private storage without valid ownership'
    );
  }

  // Unknown bucket: fail-closed
  throw new ForbiddenError(`Access denied: Storage bucket '${bucket}' is unrecognized or restricted`);
}

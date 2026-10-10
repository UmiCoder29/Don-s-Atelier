# Don's Atelier — API Route Inventory

| Path | Exported Methods | Auth Level | Wrapped in withErrorHandler | Body Schema .strict()? |
| :--- | :--- | :--- | :--- | :--- |
| `/api/account/profile` | GET, PATCH | `requireAuth` | Yes (All) | Yes (`updateProfileSchema.strict()`) |
| `/api/admin/audit-logs` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/custom-orders` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/custom-orders/[id]` | GET, PATCH | `requireRole ADMIN` | Yes (All) | Yes (`adminUpdateCustomOrderSchema.strict()`) |
| `/api/admin/inventory` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/orders` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/orders/[id]` | GET, PATCH | `requireRole ADMIN` | Yes (All) | Yes (`adminUpdateOrderStatusSchema.strict()`) |
| `/api/admin/products` | GET, POST | `requireRole ADMIN` | Yes (All) | Yes (`createProductSchema.strict()`) |
| `/api/admin/products/images` | POST | `requireRole ADMIN` | Yes | Yes (`jsonImageUploadSchema.strict()`) |
| `/api/admin/products/[id]` | GET, PATCH, DELETE | `requireRole ADMIN` | Yes (All) | Yes (`updateProductSchema.strict()`) |
| `/api/admin/products/[id]/archive` | POST | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/products/[id]/images` | POST | `requireRole ADMIN` | Yes | Yes (`jsonImageUploadSchema.strict()`) |
| `/api/admin/products/[id]/variants` | GET, POST | `requireRole ADMIN` | Yes (All) | Yes (`createVariantSchema.strict()`) |
| `/api/admin/summary` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/users` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/users/[id]` | GET | `requireRole ADMIN` | Yes | N/A (No request body) |
| `/api/admin/users/[id]/role` | PATCH | `requireRole ADMIN` | Yes | Yes (`updateRoleSchema.strict()`) |
| `/api/admin/variants/[id]` | GET, PATCH | `requireRole ADMIN` | Yes (All) | Yes (`updateVariantSchema.strict()`) |
| `/api/admin/variants/[id]/stock` | POST | `requireRole ADMIN` | Yes | Yes (`adjustStockSchema.strict()`) |
| `/api/auth/csrf` | GET | `anonymous` | Yes | N/A (No request body) |
| `/api/auth/login` | POST | `anonymous` | Yes | Yes (`loginSchema.strict()`) |
| `/api/auth/logout` | POST | `anonymous` | Yes | N/A (No request body) |
| `/api/auth/password-reset/confirm` | POST | `anonymous` (Token) | Yes | Yes (`passwordResetConfirmSchema.strict()`) |
| `/api/auth/password-reset/request` | POST | `anonymous` | Yes | Yes (`passwordResetRequestSchema.strict()`) |
| `/api/auth/refresh` | POST | `anonymous` (Token) | Yes | Yes (`refreshTokenSchema.strict()`) (Body optional by design; falls back to cookie) |
| `/api/auth/register` | POST | `anonymous` | Yes | Yes (`registerSchema.strict()`) |
| `/api/auth/session` | GET | `requireAuth` | Yes | N/A (No request body) |
| `/api/cart` | GET, POST, DELETE | `requireAuth` | Yes (All) | Yes (`addToCartSchema.strict()`) |
| `/api/cart/items/[id]` | PATCH, DELETE | `requireAuth` | Yes (All) | Yes (`updateCartItemSchema.strict()`) |
| `/api/categories` | GET | `anonymous` | Yes | N/A (No request body) |
| `/api/checkout` | POST | `requireVerifiedUser` | Yes | Yes (`checkoutSchema.strict()`) |
| `/api/custom-orders` | GET, POST | `requireAuth` | Yes (All) | Yes (`createCustomOrderSchema.strict()`) |
| `/api/custom-orders/[id]` | GET, PATCH | `requireAuth` | Yes (All) | Yes (`customerEditCustomOrderSchema.strict()`) |
| `/api/custom-orders/[id]/accept` | POST | `requireAuth` | Yes | Yes (`acceptCustomOrderQuoteSchema.strict()`) |
| `/api/custom-orders/[id]/attachments` | POST | `requireAuth` | Yes | Yes (`uploadAttachmentSchema.strict()`) |
| `/api/custom-orders/[id]/attachments/[attachmentId]` | GET | `requireAuth` | Yes | N/A (No request body) |
| `/api/custom-orders/[id]/messages` | POST | `requireAuth` | Yes | Yes (`addCustomOrderNoteSchema.strict()`) |
| `/api/custom-orders/[id]/notes` | POST | `requireRole('ADMIN')` | Yes | Yes (`addCustomOrderNoteSchema.strict()`) |
| `/api/custom-orders/[id]/whatsapp` | GET | `requireAuth` | Yes | N/A (No request body) |
| `/api/custom-orders/[id]/withdraw` | POST | `requireAuth` | Yes | Yes (`withdrawCustomOrderSchema.strict()`) (Body optional by design) |
| `/api/health` | GET, HEAD | `anonymous` | Yes (All) | N/A (No request body) |
| `/api/orders` | GET | `requireAuth` | Yes | N/A (No request body) |
| `/api/orders/[id]` | GET | `requireAuth` | Yes | N/A (No request body) |
| `/api/orders/[id]/cancel` | POST | `requireAuth` | Yes | N/A (No request body) |
| `/api/products` | GET | `anonymous` | Yes | N/A (No request body) |
| `/api/products/[slug]` | GET | `anonymous` | Yes | N/A (No request body) |
| `/api/internal/jobs/cancel-expired-orders` | POST | `Bearer CRON_SECRET` (Machine-to-machine) | Yes | N/A (No request body) |
| `/api/uploads` | POST | `requireAuth` (Showcase: ADMIN) | Yes | Yes (`initiateUploadSchema.strict()`) |
| `/api/uploads/signed-url` | POST | `requireAuth` (Catalog: ADMIN) | Yes | Yes (`signedUrlRequestSchema.strict()`) |
| `/api/webhooks/payments` | POST | `webhook signature` | Yes | N/A (HMAC webhook payload) |

---

## Upload Storage Permissions Matrix

| Route | Target / Folder | Target Bucket | Who May Use It | Constraints & Path Isolation |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/uploads` | `custom-orders` | `custom-order-uploads` | `CUSTOMER`, `ADMIN` (`requireAuth`) | Server creates signed upload URL with path `custom-orders/${user.id}/${uuid}.${ext}` |
| `POST /api/uploads` | `showcase` | `product-images` | `ADMIN` only (`requireRole ADMIN`) | Non-admins rejected with 403. Path generated: `catalog/${uuid}.${ext}` |
| `POST /api/uploads/signed-url` | `custom-order-uploads` (Upload) | `custom-order-uploads` | `CUSTOMER`, `ADMIN` (`requireAuth`) | Object path strictly server-generated under `custom-orders/${user.id}/${uuid}.${ext}` |
| `POST /api/uploads/signed-url` | `product-images` or `catalog/*` (Upload) | `product-images` | `ADMIN` only (`requireRole ADMIN`) | Non-admins rejected with 403 Forbidden |
| `POST /api/uploads/signed-url` | `custom-order-uploads` (Download) | `custom-order-uploads` | Order Owner, `ADMIN` | Enforces `assertStorageAccess`: non-owner customers rejected with 403 Forbidden |
| `POST /api/uploads/signed-url` | `product-images` (Download) | `product-images` | Public / Authenticated | Public showcase bucket |

### Storage Inspection Utilities (Read-Only)
- **`findOrphanedCustomOrderUploads()`**:
  - *Location*: `src/services/bespoke/attachment-sanitizer.ts`
  - *Purpose*: Read-only operational inspection utility that queries the `custom-order-uploads` Supabase Storage bucket and cross-references active records in `custom_order_attachments`.
  - *Behavior*: Lists storage objects created more than 24 hours ago that have no database attachment row. Exposes NO public API endpoint, performs NO file deletions, and makes zero mutations.

---

## CSRF-Exempt Routes & Security Rationale

CSRF protection in Don's Atelier is automatically applied across all mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`) executed by browser clients using ambient session cookies (`AUTH_ACCESS_COOKIE`). The following routes are exempt with documented architectural rationales:

1. **`POST /api/internal/jobs/cancel-expired-orders`**:
   - *Rationale*: Machine-to-machine internal scheduled job (cron runner). Authenticated strictly via constant-time verification of `Authorization: Bearer <CRON_SECRET>` (minimum 32 characters required in env). Ambient browser cookies and user sessions are explicitly rejected with 401. Exempted from CSRF checks (`skipCsrf: true`) as cross-site browser requests cannot inject custom `Authorization` headers.
2. **`POST /api/webhooks/payments`**:
   - *Rationale*: Machine-to-machine integration with payment providers (Stripe-shaped). Authenticated through cryptographic HMAC-SHA256 signatures (`stripe-signature` header), not ambient browser session cookies. Explicitly bypassed in `async-handler.ts`.
3. **`POST /api/auth/login`**:
   - *Rationale*: Pre-authentication route. The user does not yet possess an authenticated session cookie prior to sign-in; CSRF validation requires an active session cookie to match.
4. **`POST /api/auth/register`**:
   - *Rationale*: Pre-authentication route for new customer onboarding; no authenticated session cookie exists.
5. **`POST /api/auth/password-reset/request`**:
   - *Rationale*: Unauthenticated customer self-service password recovery initiation.
6. **`POST /api/auth/password-reset/confirm`**:
   - *Rationale*: Authenticated via short-lived cryptographic email recovery Bearer token in the `Authorization` header, not ambient cookies.
7. **`POST /api/auth/refresh`** (when called without ambient access cookie):
   - *Rationale*: Token refresh mechanism. If no access cookie is attached, it operates on the refresh token. (If an access cookie is attached, CSRF verification applies).
8. **All API Calls using `Authorization: Bearer <token>`**:
   - *Rationale*: Requests bearing an explicit Bearer token are immune to Cross-Site Request Forgery because web browsers never automatically attach custom `Authorization` headers to cross-site requests.

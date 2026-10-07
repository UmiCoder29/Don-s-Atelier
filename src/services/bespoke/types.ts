import { z } from 'zod';
import { suitMeasurementsSchema, paginationSchema, uuidSchema, priceInCentsSchema } from '@/lib/validation/zod-helpers';
import { sanitizeText } from '@/lib/validation/sanitizer';
import { CustomOrderStatus } from '@prisma/client';

export const customMeasurementItemSchema = z.object({
  key: z.string().min(1, 'Measurement key is required').max(50),
  value: z
    .number()
    .positive('Measurement value must be positive')
    .max(500, 'Measurement exceeds plausible bounds'),
  unit: z.enum(['inches', 'cm', 'kg'], {
    errorMap: () => ({ message: "Unit must be either 'inches', 'cm', or 'kg'" }),
  }),
  label: z.string().max(100).optional(),
}).strict();

export const structuredMeasurementsSchema = z
  .object({
    unit: z
      .enum(['inches', 'cm', 'kg'], {
        errorMap: () => ({ message: "Unit must be either 'inches', 'cm', or 'kg'" }),
      })
      .default('inches'),
    chest: z.number().positive('Chest measurement must be positive').max(250, 'Measurement exceeds plausible bounds').optional(),
    waist: z.number().positive('Waist measurement must be positive').max(250, 'Measurement exceeds plausible bounds').optional(),
    hips: z.number().positive('Hips measurement must be positive').max(250, 'Measurement exceeds plausible bounds').optional(),
    shoulderWidth: z.number().positive('Shoulder width must be positive').max(150, 'Measurement exceeds plausible bounds').optional(),
    sleeveLength: z.number().positive('Sleeve length must be positive').max(150, 'Measurement exceeds plausible bounds').optional(),
    jacketLength: z.number().positive('Jacket length must be positive').max(200, 'Measurement exceeds plausible bounds').optional(),
    trouserInseam: z.number().positive('Trouser inseam must be positive').max(200, 'Measurement exceeds plausible bounds').optional(),
    trouserOutseam: z.number().positive('Trouser outseam must be positive').max(250, 'Measurement exceeds plausible bounds').optional(),
    neck: z.number().positive('Neck measurement must be positive').max(100, 'Measurement exceeds plausible bounds').optional(),
    height: z.number().positive('Height must be positive').max(300, 'Measurement exceeds plausible bounds').optional(),
    weight: z.number().positive('Weight must be positive').max(500, 'Measurement exceeds plausible bounds').optional(),
  })
  .strict()
  .refine(
    (data) => {
      const { unit: _unit, ...rest } = data;
      return Object.values(rest).some((v) => v !== undefined);
    },
    { message: 'At least one anatomical measurement must be provided' }
  );

export const customOrderMeasurementsSchema = z.union([
  suitMeasurementsSchema,
  structuredMeasurementsSchema,
  z.array(customMeasurementItemSchema).min(1, 'At least one measurement required if providing array'),
]);

export const customOrderAttachmentInputSchema = z.object({
  storagePath: z.string().min(1, 'Storage path is required').max(500, 'Storage path too long'),
  fileName: z.string().max(255).optional().transform((val) => (val ? sanitizeText(val) : undefined)),
  mimeType: z.enum(['image/jpeg', 'image/png', 'image/webp']).optional().default('image/jpeg'),
  size: z.number().int().positive().max(10 * 1024 * 1024, 'File size exceeds maximum allowed limit of 10MB').optional().default(1024),
}).strict();

export const createCustomOrderSchema = z
  .object({
    description: z
      .string()
      .min(10, 'Please describe your desired bespoke suit in at least 10 characters')
      .max(2000, 'Description cannot exceed 2000 characters')
      .transform(sanitizeText),
    occasion: z
      .string()
      .max(100, 'Occasion cannot exceed 100 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    budgetRange: z
      .string()
      .max(100, 'Budget range cannot exceed 100 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    fabricPreference: z
      .string()
      .max(200, 'Fabric preference cannot exceed 200 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    fabricPreferences: z
      .string()
      .max(200, 'Fabric preference cannot exceed 200 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    stylePreference: z
      .string()
      .max(200, 'Style preference cannot exceed 200 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    stylePreferences: z
      .string()
      .max(200, 'Style preference cannot exceed 200 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    notes: z
      .string()
      .max(1000, 'Notes cannot exceed 1000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    measurements: customOrderMeasurementsSchema.optional(),
    attachments: z
      .array(customOrderAttachmentInputSchema)
      .max(5, 'Maximum of 5 reference images allowed')
      .optional(),
    attachmentIds: z
      .array(uuidSchema)
      .max(5, 'Maximum of 5 reference images allowed')
      .optional(),
    referenceImages: z
      .array(z.string().min(1).max(500).or(customOrderAttachmentInputSchema))
      .max(5, 'Maximum of 5 reference images allowed')
      .optional(),
  })
  .strict()
  .refine(
    (data) => {
      const count =
        (data.attachments?.length || 0) +
        (data.attachmentIds?.length || 0) +
        (data.referenceImages?.length || 0);
      return count <= 5;
    },
    {
      message: 'Cannot exceed a total of 5 reference images',
      path: ['attachments'],
    }
  );

export type CreateCustomOrderInput = z.infer<typeof createCustomOrderSchema>;

export const addCustomOrderNoteSchema = z
  .object({
    note: z
      .string()
      .min(1, 'Note or message cannot be empty')
      .max(1000, 'Note cannot exceed 1000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    message: z
      .string()
      .min(1, 'Note or message cannot be empty')
      .max(1000, 'Message cannot exceed 1000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict()
  .refine((data) => !!(data.note || data.message), {
    message: 'Either note or message must be provided',
  });

export type AddCustomOrderNoteInput = z.infer<typeof addCustomOrderNoteSchema>;

export const withdrawCustomOrderSchema = z
  .object({
    reason: z
      .string()
      .max(500, 'Reason cannot exceed 500 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict();

export type WithdrawCustomOrderInput = z.infer<typeof withdrawCustomOrderSchema>;

export const updateCustomOrderSchema = z
  .object({
    status: z.nativeEnum(CustomOrderStatus).optional(),
    quotedPriceInCents: priceInCentsSchema.optional(),
    notes: z
      .string()
      .max(1000, 'Notes cannot exceed 1000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    message: z
      .string()
      .max(1000, 'Message cannot exceed 1000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    expectedPriceInCents: priceInCentsSchema.optional(),
    internalNotes: z
      .string()
      .max(2000, 'Internal notes cannot exceed 2000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict();

export type UpdateCustomOrderInput = z.infer<typeof updateCustomOrderSchema>;

export const customOrderQuotedPriceSchema = z
  .number({ required_error: 'Quoted price in cents is required' })
  .int('Quoted price must be an integer in cents')
  .positive('Quoted price must be positive')
  .min(1000, 'Quoted price must be at least 1,000 cents ($10.00)')
  .max(50_000_000, 'Quoted price cannot exceed 50,000,000 cents ($500,000.00)');

export const customerEditCustomOrderSchema = z
  .object({
    description: z
      .string()
      .min(10, 'Description must be at least 10 characters')
      .max(2000, 'Description cannot exceed 2000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    occasion: z
      .string()
      .max(100, 'Occasion cannot exceed 100 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    budgetRange: z
      .string()
      .max(100, 'Budget range cannot exceed 100 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    fabricPreference: z
      .string()
      .max(200, 'Fabric preference cannot exceed 200 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    stylePreference: z
      .string()
      .max(200, 'Style preference cannot exceed 200 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict();

export type CustomerEditCustomOrderInput = z.infer<typeof customerEditCustomOrderSchema>;

export const adminUpdateCustomOrderSchema = z
  .object({
    status: z.nativeEnum(CustomOrderStatus).optional(),
    quotedPriceInCents: customOrderQuotedPriceSchema.optional(),
    quotedPrice: customOrderQuotedPriceSchema.optional(), // Alias supporting integer cents
    internalNotes: z
      .string()
      .max(2000, 'Internal notes cannot exceed 2000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
    notes: z
      .string()
      .max(2000, 'Notes cannot exceed 2000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict()
  .refine(
    (data) => {
      const price = data.quotedPriceInCents !== undefined ? data.quotedPriceInCents : data.quotedPrice;
      if (price !== undefined && data.status !== undefined && data.status !== CustomOrderStatus.QUOTED) {
        return false;
      }
      return true;
    },
    {
      message: 'Quoted price can only be specified when setting or updating status to QUOTED',
      path: ['quotedPriceInCents'],
    }
  );

export type AdminUpdateCustomOrderInput = z.infer<typeof adminUpdateCustomOrderSchema>;

export const acceptCustomOrderQuoteSchema = z
  .object({
    expectedPriceInCents: customOrderQuotedPriceSchema,
    notes: z
      .string()
      .max(1000, 'Notes cannot exceed 1000 characters')
      .optional()
      .transform((val) => (val ? sanitizeText(val) : undefined)),
  })
  .strict();

export type AcceptCustomOrderQuoteInput = z.infer<typeof acceptCustomOrderQuoteSchema>;

export const listCustomOrdersQuerySchema = paginationSchema
  .extend({
    status: z.nativeEnum(CustomOrderStatus).optional(),
  })
  .strict();

export type ListCustomOrdersQuery = z.infer<typeof listCustomOrdersQuerySchema>;

export const customOrderIdParamSchema = z
  .object({
    id: uuidSchema,
  })
  .strict();



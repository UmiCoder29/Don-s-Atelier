import { z } from 'zod';
import { sanitizeText } from './sanitizer';

export const paginationSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
}).strict();

export const uuidSchema = z.string().uuid({ message: 'Invalid UUID identifier format' });

export const priceInCentsSchema = z
  .number()
  .int('Price must be an integer in cents')
  .nonnegative('Price cannot be negative')
  .max(100_000_000, 'Price exceeds maximum allowable limit'); // $1M cap

export const shippingAddressSchema = z.object({
  recipientName: z
    .string()
    .min(2, 'Recipient name is required')
    .max(100, 'Recipient name cannot exceed 100 characters')
    .transform(sanitizeText),
  streetLine1: z
    .string()
    .min(3, 'Street address is required')
    .max(200, 'Street line 1 cannot exceed 200 characters')
    .transform(sanitizeText),
  streetLine2: z
    .string()
    .max(200, 'Street line 2 cannot exceed 200 characters')
    .optional()
    .transform((val) => (val ? sanitizeText(val) : undefined)),
  city: z
    .string()
    .min(2, 'City is required')
    .max(100, 'City cannot exceed 100 characters')
    .transform(sanitizeText),
  stateOrProvince: z
    .string()
    .min(2, 'State or province is required')
    .max(100, 'State or province cannot exceed 100 characters')
    .transform(sanitizeText),
  postalCode: z
    .string()
    .min(3, 'Postal code is required')
    .max(20, 'Postal code cannot exceed 20 characters')
    .transform(sanitizeText),
  country: z
    .string()
    .length(2, 'Country must be a 2-letter ISO code')
    .toUpperCase(),
  phone: z
    .string()
    .min(7, 'Valid contact phone number is required')
    .max(30, 'Phone cannot exceed 30 characters')
    .transform(sanitizeText),
}).strict();

export type ShippingAddress = z.infer<typeof shippingAddressSchema>;

export const suitMeasurementsSchema = z.object({
  chestInInches: z.number().positive().max(150, 'Measurement exceeds plausible bounds'),
  waistInInches: z.number().positive().max(150, 'Measurement exceeds plausible bounds'),
  hipsInInches: z.number().positive().max(150, 'Measurement exceeds plausible bounds'),
  shoulderWidthInInches: z.number().positive().max(80, 'Measurement exceeds plausible bounds'),
  sleeveLengthInInches: z.number().positive().max(80, 'Measurement exceeds plausible bounds'),
  jacketLengthInInches: z.number().positive().max(100, 'Measurement exceeds plausible bounds'),
  trouserInseamInInches: z.number().positive().max(100, 'Measurement exceeds plausible bounds'),
  trouserOutseamInInches: z.number().positive().max(120, 'Measurement exceeds plausible bounds'),
  neckInInches: z.number().positive().max(50, 'Measurement exceeds plausible bounds').optional(),
  heightInCm: z.number().positive().max(300, 'Measurement exceeds plausible bounds').optional(),
  weightInKg: z.number().positive().max(500, 'Measurement exceeds plausible bounds').optional(),
  postureNotes: z
    .string()
    .max(500, 'Posture notes cannot exceed 500 characters')
    .optional()
    .transform((val) => (val ? sanitizeText(val) : undefined)),
}).strict();

export type SuitMeasurements = z.infer<typeof suitMeasurementsSchema>;

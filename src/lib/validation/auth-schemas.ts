import { z } from 'zod';
import { Role } from '@prisma/client';
import { sanitizeText } from './sanitizer';

/**
 * Strict Password Policy for Don's Atelier:
 * - Minimum 8 characters
 * - Maximum 128 characters
 * - At least one uppercase letter (A-Z)
 * - At least one lowercase letter (a-z)
 * - At least one numeric digit (0-9)
 * - At least one special symbol (!@#$%^&*...)
 */
export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long')
  .max(128, 'Password cannot exceed 128 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

export const registerSchema = z.object({
  email: z.string().email('Valid email address is required').max(255, 'Email cannot exceed 255 characters').toLowerCase().trim(),
  password: passwordSchema,
  name: z.string().min(2, 'Name must be at least 2 characters').max(100, 'Name cannot exceed 100 characters').transform(sanitizeText),
  phone: z.string().max(30, 'Phone cannot exceed 30 characters').optional().transform((val) => (val ? sanitizeText(val) : undefined)),
  role: z.string().optional(), // Allowed in input schema so server can sanitize and strictly force CUSTOMER
}).strict();

export type RegisterInput = z.infer<typeof registerSchema>;

export const loginSchema = z.object({
  email: z.string().email('Valid email address is required').max(255, 'Email cannot exceed 255 characters').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required').max(128, 'Password cannot exceed 128 characters'),
}).strict();

export type LoginInput = z.infer<typeof loginSchema>;

export const passwordResetRequestSchema = z.object({
  email: z.string().email('Valid email address is required').max(255, 'Email cannot exceed 255 characters').toLowerCase().trim(),
  redirectTo: z.string().url('Invalid redirect URL').max(500, 'Redirect URL cannot exceed 500 characters').optional(),
}).strict();

export type PasswordResetRequestInput = z.infer<typeof passwordResetRequestSchema>;

export const passwordResetConfirmSchema = z.object({
  password: passwordSchema,
}).strict();

export type PasswordResetConfirmInput = z.infer<typeof passwordResetConfirmSchema>;

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required').max(2048, 'Refresh token is too long').optional(),
}).strict();

export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;

export const updateRoleSchema = z.object({
  role: z.nativeEnum(Role, { errorMap: () => ({ message: 'Invalid role. Must be CUSTOMER or ADMIN' }) }),
}).strict();

export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;

export const updateProfileSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100, 'Name cannot exceed 100 characters').optional().transform((val) => (val ? sanitizeText(val) : undefined)),
  phone: z.string().max(30, 'Phone cannot exceed 30 characters').optional().nullable().transform((val) => (val ? sanitizeText(val) : val)),
}).strict();

export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;

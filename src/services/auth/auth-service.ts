import { prisma } from '@/lib/db/prisma';
import { supabaseAdmin, createSupabaseUserClient } from '@/lib/db/supabase';
import { Role } from '@prisma/client';
import {
  BadRequestError,
  ConflictError,
  UnauthorizedError,
  NotFoundError,
  ForbiddenError,
} from '@/lib/errors/api-error';
import {
  RegisterInput,
  LoginInput,
  PasswordResetRequestInput,
  PasswordResetConfirmInput,
  UpdateRoleInput,
} from '@/lib/validation/auth-schemas';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';
import { encryptPhone } from '@/lib/crypto/field-encryption';
import { logAuditEvent } from '@/lib/audit/audit-logger';
import { rateLimiter } from '@/lib/security/rate-limiter';

export interface AuthSessionResult {
  user: {
    id: string;
    email: string;
    name?: string | null;
    role: Role;
    emailConfirmed: boolean;
  };
  tokens?: {
    accessToken: string;
    refreshToken: string;
    expiresIn?: number;
  };
  emailConfirmationRequired?: boolean;
}

/**
 * Service managing customer and administrator authentication,
 * session lifecycle, and credential updates for Don's Atelier.
 */
export class AuthService {
  /**
   * Registers a new customer in Supabase Auth and auto-initializes their Profile in Postgres.
   */
  async register(
    input: RegisterInput,
    context?: { ip?: string | null; userAgent?: string | null }
  ): Promise<AuthSessionResult> {
    // 1. Create account in Supabase Auth
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: input.email,
      password: input.password,
      email_confirm: true, // Auto-confirm in testing/dev; prod requires verification flow
      user_metadata: {
        name: input.name,
      },
    });

    if (authError) {
      if (
        authError.message.toLowerCase().includes('already registered') ||
        authError.message.toLowerCase().includes('already exists')
      ) {
        throw new ConflictError('An account with this email address already exists');
      }
      throw new BadRequestError(`Registration failed: ${authError.message}`);
    }

    if (!authData.user) {
      throw new BadRequestError('Registration could not be completed at this time');
    }

    const userId = authData.user.id;
    const encryptedPhone = input.phone ? encryptPhone(input.phone) : null;

    // 2. Strict: Auto-create Profile with role CUSTOMER and encrypted phone
    const profile = await prisma.profile.upsert({
      where: { id: userId },
      create: {
        id: userId,
        email: input.email,
        name: input.name,
        phone: encryptedPhone,
        role: Role.CUSTOMER, // Admin role can never be set by a request body
      },
      update: {
        name: input.name,
        phone: encryptedPhone,
      },
    });

    // 3. Auto-initialize shopping cart for the new customer
    await prisma.cart.upsert({
      where: { profileId: userId },
      create: { profileId: userId },
      update: {},
    });

    // 4. Record audit log using centralized audit helper
    await logAuditEvent({
      actorId: userId,
      action: 'USER_REGISTERED',
      entity: 'Profile',
      entityId: userId,
      metadata: {
        email: input.email,
        role: Role.CUSTOMER,
      },
      ip: context?.ip,
      userAgent: context?.userAgent,
    });

    return {
      user: {
        id: profile.id,
        email: profile.email,
        name: profile.name,
        role: profile.role,
        emailConfirmed: Boolean(authData.user.email_confirmed_at),
      },
      emailConfirmationRequired: !authData.user.email_confirmed_at,
    };
  }

  /**
   * Authenticates a user with email and password.
   * Strictly adheres to non-enumeration: returns generic "Invalid email or password" error.
   */
  async login(
    input: LoginInput,
    context?: { ip?: string | null; userAgent?: string | null }
  ): Promise<AuthSessionResult> {
    const normalizedEmail = input.email.trim().toLowerCase();

    // 1. Per-target-email throttling: 5 failed attempts per 15 minutes per normalized email (independent of IP)
    if (rateLimiter.isEmailThrottled(normalizedEmail)) {
      const existingProfile = await prisma.profile.findUnique({
        where: { email: normalizedEmail },
        select: { id: true },
      });

      await logAuditEvent({
        actorId: existingProfile?.id || null,
        action: 'USER_LOGIN_FAILED',
        entity: 'Profile',
        entityId: existingProfile?.id || 'unauthenticated',
        metadata: {
          emailAttempted: input.email,
          reason: 'Too many failed login attempts for this email address',
        },
        ip: context?.ip,
        userAgent: context?.userAgent,
      });

      // Exact same generic error as normal failed login: 401 Unauthorized, never reveals account existence
      throw new UnauthorizedError('Invalid email or password');
    }

    const supabase = createSupabaseUserClient();

    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: input.email,
      password: input.password,
    });

    if (authError || !authData.session || !authData.user) {
      // Record failed login attempt for this normalized email (applies to existing and non-existing emails)
      rateLimiter.recordEmailFailure(normalizedEmail);

      // Find whether a profile exists for this email so we can record actorId if known
      const existingProfile = await prisma.profile.findUnique({
        where: { email: normalizedEmail },
        select: { id: true },
      });

      // Record failed login audit attempt
      await logAuditEvent({
        actorId: existingProfile?.id || null,
        action: 'USER_LOGIN_FAILED',
        entity: 'Profile',
        entityId: existingProfile?.id || 'unauthenticated',
        metadata: {
          emailAttempted: input.email,
        },
        ip: context?.ip,
        userAgent: context?.userAgent,
      });

      // Non-enumeration rule: Never leak whether the email exists or password was wrong
      throw new UnauthorizedError('Invalid email or password');
    }

    // Reset failed attempt counter upon successful login
    rateLimiter.resetEmailFailures(normalizedEmail);

    // Fetch corresponding profile
    let profile = await prisma.profile.findUnique({
      where: { id: authData.user.id },
    });

    if (!profile) {
      const displayName = (authData.user.user_metadata?.name || '') as string;
      profile = await prisma.profile.create({
        data: {
          id: authData.user.id,
          email: authData.user.email!,
          name: displayName || null,
          role: Role.CUSTOMER,
        },
      });
    }

    // Record login audit
    await logAuditEvent({
      actorId: profile.id,
      action: 'USER_LOGIN_SUCCESS',
      entity: 'Profile',
      entityId: profile.id,
      metadata: {
        email: profile.email,
        role: profile.role,
      },
      ip: context?.ip,
      userAgent: context?.userAgent,
    });

    return {
      user: {
        id: profile.id,
        email: profile.email,
        name: profile.name,
        role: profile.role,
        emailConfirmed: Boolean(authData.user.email_confirmed_at),
      },
      tokens: {
        accessToken: authData.session.access_token,
        refreshToken: authData.session.refresh_token,
        expiresIn: authData.session.expires_in,
      },
    };
  }

  /**
   * Refreshes an expired session using a refresh token.
   */
  async refreshSession(refreshToken: string): Promise<AuthSessionResult> {
    const supabase = createSupabaseUserClient();

    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });

    if (error || !data.session || !data.user) {
      throw new UnauthorizedError('Session has expired or refresh token is invalid. Please sign in again.');
    }

    const profile = await prisma.profile.findUnique({
      where: { id: data.user.id },
    });

    if (!profile) {
      throw new NotFoundError('User profile');
    }

    await logAuditEvent({
      actorId: profile.id,
      action: 'SESSION_REFRESHED',
      entity: 'Profile',
      entityId: profile.id,
    });

    return {
      user: {
        id: profile.id,
        email: profile.email,
        name: profile.name,
        role: profile.role,
        emailConfirmed: Boolean(data.user.email_confirmed_at),
      },
      tokens: {
        accessToken: data.session.access_token,
        refreshToken: data.session.refresh_token,
        expiresIn: data.session.expires_in,
      },
    };
  }

  /**
   * Signs out a user and invalidates the session in Supabase Auth.
   * Ensures the session and token are revoked on the server rather than just client-side.
   */
  async logout(
    accessToken?: string,
    context?: { ip?: string | null; userAgent?: string | null; actorId?: string | null }
  ): Promise<void> {
    if (accessToken) {
      try {
        await supabaseAdmin.auth.admin.signOut(accessToken, 'local');
      } catch {
        const supabase = createSupabaseUserClient(accessToken);
        await supabase.auth.signOut();
      }

      await logAuditEvent({
        actorId: context?.actorId || null,
        action: 'USER_LOGOUT',
        entity: 'Session',
        entityId: context?.actorId || 'current',
        ip: context?.ip,
        userAgent: context?.userAgent,
      });
    }
  }

  /**
   * Sends password reset instructions.
   * Generic response prevents account enumeration.
   */
  async requestPasswordReset(input: PasswordResetRequestInput): Promise<{ message: string }> {
    const supabase = createSupabaseUserClient();

    await supabase.auth.resetPasswordForEmail(input.email, {
      redirectTo: input.redirectTo,
    });

    await logAuditEvent({
      action: 'PASSWORD_RESET_REQUESTED',
      entity: 'Profile',
      entityId: 'email_requested',
      metadata: {
        email: input.email,
      },
    });

    // Generic response regardless of whether email exists
    return {
      message: 'If an account exists with this email address, a password reset link has been dispatched.',
    };
  }

  /**
   * Confirms password reset with an authenticated recovery access token.
   */
  async confirmPasswordReset(accessToken: string, input: PasswordResetConfirmInput): Promise<{ message: string }> {
    const supabase = createSupabaseUserClient(accessToken);

    const { data, error } = await supabase.auth.updateUser({
      password: input.password,
    });

    if (error) {
      throw new BadRequestError(`Password update failed: ${error.message}`);
    }

    if (data?.user?.id) {
      await logAuditEvent({
        actorId: data.user.id,
        action: 'PASSWORD_RESET_CONFIRMED',
        entity: 'Profile',
        entityId: data.user.id,
      });
    }

    return {
      message: 'Password has been successfully updated. You may now sign in with your new credentials.',
    };
  }

  /**
   * Allows an existing ADMIN to promote or change a user's role.
   * Admin role can strictly ONLY be assigned by another admin.
   */
  async setUserRole(adminUser: AuthenticatedUser, targetUserId: string, input: UpdateRoleInput) {
    if (adminUser.role !== Role.ADMIN) {
      throw new ForbiddenError('Only administrators can modify user roles');
    }

    const targetProfile = await prisma.profile.findUnique({
      where: { id: targetUserId },
    });

    if (!targetProfile) {
      throw new NotFoundError('User profile');
    }

    const updated = await prisma.profile.update({
      where: { id: targetUserId },
      data: { role: input.role },
    });

    await logAuditEvent({
      actorId: adminUser.id,
      action: 'USER_ROLE_UPDATED',
      entity: 'Profile',
      entityId: targetUserId,
      metadata: {
        previousRole: targetProfile.role,
        newRole: input.role,
        updatedBy: adminUser.id,
      },
    });

    return {
      id: updated.id,
      email: updated.email,
      name: updated.name,
      role: updated.role,
    };
  }
}

export const authService = new AuthService();

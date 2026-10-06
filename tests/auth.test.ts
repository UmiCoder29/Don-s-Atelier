import { describe, it, expect } from 'vitest';
import { Role } from '@prisma/client';
import { assertOwnerOrAdmin } from '@/lib/auth/assert-owner-or-admin';
import { ForbiddenError, UnauthorizedError } from '@/lib/errors/api-error';
import { AuthenticatedUser } from '@/lib/auth/supabase-auth';

describe('Auth & RBAC - assertOwnerOrAdmin Helper', () => {
  const customerA: AuthenticatedUser = {
    id: 'user-aaa-111',
    email: 'customer.a@example.com',
    role: Role.CUSTOMER,
    name: 'Customer A',
    emailConfirmed: true,
  };

  const customerB: AuthenticatedUser = {
    id: 'user-bbb-222',
    email: 'customer.b@example.com',
    role: Role.CUSTOMER,
    name: 'Customer B',
    emailConfirmed: true,
  };

  const adminUser: AuthenticatedUser = {
    id: 'admin-999',
    email: 'admin@dons-atelier.com',
    role: Role.ADMIN,
    name: 'Master Tailor Admin',
    emailConfirmed: true,
  };

  it('allows access when user is the resource owner', () => {
    expect(() => {
      assertOwnerOrAdmin(customerA, 'user-aaa-111');
    }).not.toThrow();
  });

  it('allows access when user is an ADMIN, regardless of resource owner', () => {
    expect(() => {
      assertOwnerOrAdmin(adminUser, 'user-aaa-111');
      assertOwnerOrAdmin(adminUser, 'user-bbb-222');
      assertOwnerOrAdmin(adminUser, 'non-existent-user');
    }).not.toThrow();
  });

  it('throws ForbiddenError when a customer attempts to access another customer resource', () => {
    expect(() => {
      assertOwnerOrAdmin(customerA, 'user-bbb-222');
    }).toThrow(ForbiddenError);

    expect(() => {
      assertOwnerOrAdmin(customerB, 'user-aaa-111');
    }).toThrow('You do not have permission to access or modify this resource');
  });

  it('throws UnauthorizedError when user is null or undefined', () => {
    expect(() => {
      assertOwnerOrAdmin(null, 'user-aaa-111');
    }).toThrow(UnauthorizedError);

    expect(() => {
      assertOwnerOrAdmin(undefined, 'user-aaa-111');
    }).toThrow('Authentication required to access this resource');
  });

  it('accepts custom error message for ForbiddenError', () => {
    expect(() => {
      assertOwnerOrAdmin(customerA, 'user-bbb-222', 'Custom bespoke order access denied');
    }).toThrow('Custom bespoke order access denied');
  });
});

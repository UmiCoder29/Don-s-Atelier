import { Role } from './roles';

/**
 * Represents the actor executing an operation in Don's Atelier:
 * - USER: An authenticated human user with an ID and Role (CUSTOMER or ADMIN).
 * - SYSTEM: An automated backend process (e.g. payment_webhook, checkout_payment, expired_order_scheduler).
 */
export type Actor =
  | { kind: 'USER'; id: string; role: Role }
  | { kind: 'SYSTEM'; name: string };

export function userActor(id: string, role: Role): Actor {
  return { kind: 'USER', id, role };
}

export function systemActor(name: string): Actor {
  return { kind: 'SYSTEM', name };
}

export function isUserActor(actor: Actor): actor is { kind: 'USER'; id: string; role: Role } {
  return actor.kind === 'USER';
}

export function isSystemActor(actor: Actor): actor is { kind: 'SYSTEM'; name: string } {
  return actor.kind === 'SYSTEM';
}

import { CustomOrderStatus } from '@prisma/client';

/**
 * Status change notification payload.
 *
 * Privacy Rule:
 * Payload contains ONLY the reference code and the new status.
 * Strictly NO personal data (names, emails, measurements, notes, phone numbers).
 */
export interface StatusChangeNotificationPayload {
  readonly referenceCode: string;
  readonly newStatus: CustomOrderStatus;
}

/**
 * Contract for dispatching transactional notifications on custom order lifecycle events.
 */
export interface NotificationService {
  /**
   * Dispatches a notification when an order changes status.
   * Must only be invoked AFTER the database transaction commits.
   */
  sendStatusChangeNotification(payload: StatusChangeNotificationPayload): Promise<void>;
}

/**
 * Mock / Logging implementation of NotificationService.
 * Can be swapped with a real email/SMS delivery provider.
 */
export class MockEmailNotificationService implements NotificationService {
  private lastDispatchedPayload: StatusChangeNotificationPayload | null = null;
  private shouldFail: boolean = false;

  /**
   * For testing: configure whether sending notifications throws an error.
   */
  public setShouldFail(fail: boolean): void {
    this.shouldFail = fail;
  }

  /**
   * For testing: inspect the last payload dispatched.
   */
  public getLastDispatchedPayload(): StatusChangeNotificationPayload | null {
    return this.lastDispatchedPayload;
  }

  public reset(): void {
    this.lastDispatchedPayload = null;
    this.shouldFail = false;
  }

  async sendStatusChangeNotification(payload: StatusChangeNotificationPayload): Promise<void> {
    if (this.shouldFail) {
      throw new Error('[NotificationService Mock] Simulated notification delivery failure');
    }

    this.lastDispatchedPayload = { ...payload };
    // Production logger (no personal data)
    // console.info(`[NotificationService] Order ${payload.referenceCode} moved to ${payload.newStatus}`);
  }
}

// Global default singleton instance
export const notificationService = new MockEmailNotificationService();

/**
 * Backfill Script: Mark custom_order_status_history rows as isInternal = true
 * if the decrypted note plaintext begins with the [INTERNAL] marker.
 *
 * Security & Integrity Guarantees:
 * 1. Reads database credentials and encryption keys strictly from environment variables.
 * 2. Default mode is DRY RUN. Requires explicit --apply flag to commit changes.
 * 3. Never prints secrets or plaintext note contents (counts only).
 * 4. Never rewrites, re-encrypts, or mutates note text.
 * 5. Aborts immediately if decrypt failures > 0 (fail-safe).
 * 6. In apply mode, runs inside an atomic transaction with a complete re-scan verification.
 *
 * Usage:
 *   npx tsx scripts/backfill-is-internal.ts          # Dry run
 *   npx tsx scripts/backfill-is-internal.ts --apply  # Apply in transaction
 */

import { PrismaClient } from '@prisma/client';
import { decryptField } from '../src/lib/crypto/field-encryption';

const INTERNAL_NOTE_PREFIX = '[INTERNAL]';

async function main() {
  const isApplyMode = process.argv.includes('--apply');
  console.log(`[Backfill] Running in ${isApplyMode ? 'APPLY' : 'DRY RUN'} mode...`);

  const prisma = new PrismaClient();

  try {
    const rows = await prisma.$queryRawUnsafe<{ id: string; note: string | null; isInternal: boolean }[]>(
      `SELECT id, note, "isInternal" FROM "custom_order_status_history"`
    );

    let totalRows = rows.length;
    let rowsFlagged = 0;
    let rowsAlreadyFlagged = 0;
    let decryptFailures = 0;
    const idsToMarkInternal: string[] = [];

    for (const row of rows) {
      if (row.isInternal) {
        rowsAlreadyFlagged++;
      }

      if (!row.note) {
        continue;
      }

      let plaintext: string;
      try {
        plaintext = decryptField(row.note);
      } catch {
        decryptFailures++;
        continue;
      }

      if (plaintext.startsWith(INTERNAL_NOTE_PREFIX)) {
        if (!row.isInternal) {
          rowsFlagged++;
          idsToMarkInternal.push(row.id);
        }
      }
    }

    console.log('[Backfill Statistics]');
    console.log(`- Total rows scanned: ${totalRows}`);
    console.log(`- Rows flagged for isInternal = true: ${rowsFlagged}`);
    console.log(`- Rows already flagged: ${rowsAlreadyFlagged}`);
    console.log(`- Decrypt failures: ${decryptFailures}`);

    if (isApplyMode) {
      if (decryptFailures > 0) {
        throw new Error(
          `Aborting backfill: ${decryptFailures} decrypt failures encountered. No database changes were made.`
        );
      }

      if (idsToMarkInternal.length === 0) {
        console.log('[Backfill] No rows require update. Apply complete.');
        return;
      }

      await prisma.$transaction(
        async (tx) => {
          const updateResult = await tx.$executeRawUnsafe(
            `UPDATE "custom_order_status_history"
             SET "isInternal" = true
             WHERE id = ANY($1::text[])`,
            idsToMarkInternal
          );

          console.log(`[Backfill] Rows updated in transaction: ${updateResult}`);

          // Post-migration full re-scan inside the same transaction:
          // Re-reads ALL rows and verifies zero rows decrypt to [INTERNAL] while isInternal = false
          const verifyRows = await tx.$queryRawUnsafe<{ id: string; note: string | null; isInternal: boolean }[]>(
            `SELECT id, note, "isInternal" FROM "custom_order_status_history"`
          );

          let lingeringUnmarkedCount = 0;
          for (const verifyRow of verifyRows) {
            if (!verifyRow.note) continue;
            try {
              const pt = decryptField(verifyRow.note);
              if (pt.startsWith(INTERNAL_NOTE_PREFIX) && !verifyRow.isInternal) {
                lingeringUnmarkedCount++;
              }
            } catch {
              throw new Error('Verification failed: encountered decryption failure during transaction re-scan.');
            }
          }

          if (lingeringUnmarkedCount > 0) {
            throw new Error(
              `Verification failed: ${lingeringUnmarkedCount} rows remained unmarked! Transaction aborted.`
            );
          }
        },
        { timeout: 30000 }
      );

      console.log('[Backfill] Verification passed: 0 marker rows remain with isInternal = false.');
    } else {
      console.log('[Backfill] Dry run complete. No database changes were applied.');
    }
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('[Backfill Error]', err instanceof Error ? err.message : 'Unknown error');
  process.exit(1);
});

import { prisma } from '../src/lib/db/prisma';
import fs from 'fs';
import path from 'path';

async function main() {
  const sqlPath = path.join(__dirname, '../prisma/migrations/20261004103000_lock_down_client_writes/migration.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  console.log('Applying migration 20261004103000_lock_down_client_writes...');
  await prisma.$executeRawUnsafe(sql);
  console.log('Migration applied successfully!');
}

main()
  .catch((err) => {
    console.error('Failed to apply migration:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

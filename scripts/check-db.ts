import { prisma } from '../src/lib/db/prisma';

async function main() {
  const rlsStatus: any = await prisma.$queryRaw`SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname='public' ORDER BY tablename`;
  console.log('RLS Status:', rlsStatus);

  const tables: any = await prisma.$queryRaw`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`;
  console.log('Tables:', tables.map((t: any) => t.table_name));

  const orderIndexes: any = await prisma.$queryRaw`SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'orders' ORDER BY indexname`;
  console.log('Order Indexes:', orderIndexes);
}

main().catch(console.error).finally(() => prisma.$disconnect());

import { prisma } from '../src/lib/db/prisma';

async function main() {
  const tables: any = await prisma.$queryRaw`
    SELECT tablename, rowsecurity 
    FROM pg_tables 
    WHERE schemaname = 'public' 
    ORDER BY tablename
  `;
  console.log('--- pg_tables (schemaname=\'public\') ---');
  for (const row of tables) {
    console.log(`table: ${row.tablename.padEnd(30)} | rowsecurity: ${row.rowsecurity}`);
  }

  const policies: any = await prisma.$queryRaw`
    SELECT tablename, policyname, cmd 
    FROM pg_policies 
    WHERE schemaname = 'public' 
    ORDER BY tablename, policyname
  `;
  console.log('\n--- pg_policies (schemaname=\'public\') ---');
  for (const pol of policies) {
    console.log(`table: ${pol.tablename.padEnd(30)} | cmd: ${pol.cmd.padEnd(8)} | policy: ${pol.policyname}`);
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

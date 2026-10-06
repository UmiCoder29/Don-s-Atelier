import { prisma } from '../src/lib/db/prisma';

async function main() {
  const policies: any = await prisma.$queryRaw`
    SELECT tablename, policyname, cmd, qual, with_check 
    FROM pg_policies 
    WHERE schemaname='public' 
      AND tablename IN ('orders','order_items','payments','carts','cart_items','addresses','profiles') 
    ORDER BY tablename, policyname
  `;

  console.log('--- pg_policies (orders, order_items, payments, carts, cart_items, addresses, profiles) ---');
  for (const pol of policies) {
    console.log(
      `table: ${pol.tablename.padEnd(14)} | policy: ${pol.policyname.padEnd(32)} | cmd: ${pol.cmd.padEnd(6)} | qual: ${String(pol.qual).replace(/\s+/g, ' ')} | with_check: ${String(pol.with_check).replace(/\s+/g, ' ')}`
    );
  }

  const grants: any = await prisma.$queryRaw`
    SELECT grantee, table_name, privilege_type 
    FROM information_schema.role_table_grants 
    WHERE table_schema='public' 
      AND grantee IN ('anon','authenticated') 
    ORDER BY table_name
  `;

  console.log('\n--- role_table_grants (anon, authenticated) ---');
  for (const grant of grants) {
    console.log(
      `grantee: ${grant.grantee.padEnd(14)} | table_name: ${grant.table_name.padEnd(28)} | privilege_type: ${grant.privilege_type}`
    );
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

import { prisma } from '../src/lib/db/prisma';

async function main() {
  console.log('--- QUERY 1: pg_policies (schemaname=public AND cmd <> SELECT) ---');
  const nonSelectPolicies: any = await prisma.$queryRaw`
    SELECT tablename, policyname, cmd 
    FROM pg_policies 
    WHERE schemaname='public' AND cmd <> 'SELECT'
    ORDER BY tablename, policyname
  `;
  console.log('Row count:', nonSelectPolicies.length);
  for (const pol of nonSelectPolicies) {
    console.log(`tablename: ${pol.tablename} | policyname: ${pol.policyname} | cmd: ${pol.cmd}`);
  }

  console.log('\n--- QUERY 2: role_table_grants (schemaname=public, grantee IN (anon, authenticated), privilege_type <> SELECT) ---');
  const nonSelectGrants: any = await prisma.$queryRaw`
    SELECT grantee, table_name, privilege_type 
    FROM information_schema.role_table_grants 
    WHERE table_schema='public' 
      AND grantee IN ('anon','authenticated') 
      AND privilege_type <> 'SELECT'
    ORDER BY grantee, table_name, privilege_type
  `;
  console.log('Row count:', nonSelectGrants.length);
  for (const grant of nonSelectGrants) {
    console.log(`grantee: ${grant.grantee} | table_name: ${grant.table_name} | privilege_type: ${grant.privilege_type}`);
  }
}

main()
  .catch((err) => {
    console.error('Error running check-applied-rls:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

import { prisma } from '../src/lib/db/prisma';

async function main() {
  const funcDef: any = await prisma.$queryRaw`
    SELECT pg_get_functiondef('public.is_admin'::regproc) as def
  `;
  console.log('--- pg_get_functiondef(is_admin) ---');
  console.log(funcDef[0]?.def);

  const roleInfo: any = await prisma.$queryRaw`
    SELECT current_user, rolbypassrls FROM pg_roles WHERE rolname = current_user
  `;
  console.log('\n--- current_user & rolbypassrls ---');
  console.log(JSON.stringify(roleInfo[0]));
}

main()
  .catch((err) => {
    console.error('ERROR in check-admin-role:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

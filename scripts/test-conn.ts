import { PrismaClient } from '@prisma/client';

async function test(port: number) {
  const url = `postgresql://postgres.zoqiuoomjmgifamfivzv:Don%27s-database2992005@aws-0-ap-southeast-1.pooler.supabase.com:${port}/postgres?sslmode=require`;
  console.log(`Testing port ${port}...`);
  const client = new PrismaClient({
    datasources: {
      db: { url }
    }
  });
  try {
    const res: any = await client.$queryRaw`SELECT 1 as val`;
    console.log(`Port ${port} SUCCESS:`, res);
  } catch (err: any) {
    console.log(`Port ${port} FAILED:`, err.message);
  } finally {
    await client.$disconnect();
  }
}

async function main() {
  await test(6543);
  await test(5432);
  await test(443);
}

main();

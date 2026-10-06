import { PrismaClient } from '@prisma/client';

async function main() {
  const p = new PrismaClient({
    datasources: {
      db: {
        url: 'postgresql://postgres.zoqiuoomjmgifamfivzv:Don%27s-database2992005@127.0.0.1:5433/postgres?sslmode=disable'
      }
    }
  });

  try {
    const res = await p.$queryRaw`SELECT 1 as val`;
    console.log('SUCCESS VIA PROXY:', res);
  } catch (err: any) {
    console.error('FAIL PROXY:', err.message);
  } finally {
    await p.$disconnect();
  }
}

main();

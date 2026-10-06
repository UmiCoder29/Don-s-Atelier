import tls from 'tls';

const host = 'aws-0-ap-southeast-1.pooler.supabase.com';
const port = 443;
const user = 'postgres.zoqiuoomjmgifamfivzv';
const database = 'postgres';

console.log(`Connecting TLS to ${host}:${port}...`);
const socket = tls.connect({ host, port, servername: host }, () => {
  console.log('TLS connected! Sending StartupMessage...');

  // Build PostgreSQL StartupMessage packet
  // protocol version 3.0: major 3, minor 0 -> 196608 (0x00030000)
  const params: Record<string, string> = {
    user,
    database,
    application_name: 'test_probe'
  };

  const paramBuffers: Buffer[] = [];
  for (const [k, v] of Object.entries(params)) {
    paramBuffers.push(Buffer.from(k, 'utf8'), Buffer.from([0]), Buffer.from(v, 'utf8'), Buffer.from([0]));
  }
  paramBuffers.push(Buffer.from([0])); // packet terminator

  const body = Buffer.concat(paramBuffers);
  const len = 4 + 4 + body.length; // total length including 4-byte len and 4-byte version

  const packet = Buffer.alloc(len);
  packet.writeInt32BE(len, 0);
  packet.writeInt32BE(196608, 4); // 3.0
  body.copy(packet, 8);

  socket.write(packet);
});

socket.on('data', (data) => {
  console.log('RECEIVED BYTES:', data.length);
  const type = String.fromCharCode(data[0]);
  console.log('Packet type:', type, '(hex:', data.slice(0, 8).toString('hex'), ')');
  if (type === 'R') {
    const authType = data.readInt32BE(5);
    console.log('Authentication request type:', authType); // 3=cleartext, 5=md5, 10=sasl (scram-sha-256)
  } else if (type === 'E') {
    console.log('Error from server:', data.toString('utf8'));
  }
  socket.destroy();
});

socket.on('error', (err) => {
  console.error('Socket error:', err);
});

socket.on('close', () => {
  console.log('Connection closed');
});

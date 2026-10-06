import net from 'net';
import tls from 'tls';

// Simple local proxy that bridges localhost:5433 -> TLS aws-0-ap-southeast-1.pooler.supabase.com:443
const server = net.createServer((clientSocket) => {
  const upstream = tls.connect(
    {
      host: 'aws-0-ap-southeast-1.pooler.supabase.com',
      port: 443,
      servername: 'aws-0-ap-southeast-1.pooler.supabase.com',
    },
    () => {
      // Once TLS connected, does Supabase pooler expect SSLRequest or StartupMessage?
      // Let's test by piping directly or handling SSLRequest
    }
  );

  let handledSsl = false;
  clientSocket.once('data', (data) => {
    // Check if client sent SSLRequest (length 8, code 80877103)
    if (data.length === 8 && data.readInt32BE(4) === 80877103) {
      // Client is asking if SSL is supported. Say 'N' (No) because upstream connection is ALREADY encrypted via TLS!
      clientSocket.write('N');
      handledSsl = true;
      // Next data from client will be the unencrypted (inside local connection) StartupMessage
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    } else {
      // Client sent StartupMessage directly (sslmode=disable on local connection)
      upstream.write(data);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    }
  });

  upstream.on('error', (err) => {
    console.error('Upstream error:', err);
    clientSocket.destroy();
  });
  clientSocket.on('error', (err) => {
    console.error('Client error:', err);
    upstream.destroy();
  });
});

server.listen(5433, '127.0.0.1', () => {
  console.log('Local TLS bridge listening on 127.0.0.1:5433');
});

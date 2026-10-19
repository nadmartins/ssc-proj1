package streamserver;

import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.Executors;

/**
 * Origin server implemented with raw sockets only (java.net.ServerSocket / Socket),
 * no com.sun.net.httpserver, no external libraries. Serves files under mediaDir at
 * GET /media/<file>, honouring a single "Range: bytes=start-end" header so seeking
 * works. Each connection handles exactly one request, then closes (Connection: close) -
 * that keeps the hand-written HTTP parsing simple.
 *
 * Usage: java OriginSocketServer [port=8081] [mediaDir=media]
 */
public class StreamServer {
    static final int BLOCK_SIZE = 1024;
    private static CryptoConfig serverConfig;
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8081;
        Path root = Paths.get(args.length > 1 ? args[1] : "media").toAbsolutePath().normalize();
        String configFile = args.length > 2 ? args[2] : "sservercrypto.config";
        serverConfig = CryptoConfig.load(configFile);
        System.out.println("Secure Stream Server on port " + port + " [" + serverConfig.toPcc() + "]");
        try (ServerSocket server = new ServerSocket(port)) {
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, root));
            }
        }
    }
    static void handle(Socket socket, Path root) {
        try (socket) {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            ProtocolMessage msg1 = ProtocolMessage.read(in);
            if (msg1 == null || msg1.getType() != ProtocolMessage.TYPE_1_PROXY_PROPOSAL) {
                sendErrorAndClose(out, "Expected Type 1 message.");
                return;
            }
            ProtocolMessage.Type1Data type1 = msg1.parseType1();
            if (!type1.pcc().equalsIgnoreCase(serverConfig.toPcc())) {
                sendErrorAndClose(out, "Proposed cryptographic configuration rejected.");
                return;
            }
            long seqY = type1.secx() + 1;
            byte[] srv = CryptoService.generateNonce(32);
            String ccc = serverConfig.toPcc();
            ProtocolMessage msg2 = ProtocolMessage.createType2(seqY, srv, ccc, serverConfig);
            msg2.send(out);
            ProtocolMessage msg3 = ProtocolMessage.read(in);
            if (msg3 == null || msg3.getType() != ProtocolMessage.TYPE_3_PROXY_REQUEST) {
                sendErrorAndClose(out, "Expected Type 3 message.");
                return;
            }
            ProtocolMessage.Type3Data type3 = msg3.parseType3(serverConfig);
            if (type3.seqz() != seqY + 1) {
                sendErrorAndClose(out, "Invalid sequence number in Type 3 message.");
                return;
            }
            byte[] expectedR = CryptoService.sha256(srv);
            if (!MessageDigest.isEqual(expectedR, type3.r())) {
                sendErrorAndClose(out, "Invalid SRV challenge response.");
                return;
            }
            Path file = root.resolve(type3.media()).normalize();
            if (!file.startsWith(root) || !Files.isRegularFile(file)) {
                sendErrorAndClose(out, "Media file not found: " + type3.media());
                return;
            }
            System.out.println("Streaming '" + type3.media() + "' to client");
            serveFile(out, file, type3.seqz());
        } catch (Exception e) {
            System.err.println("Session error: " + e.getMessage());
        }
    }
    static void serveFile(OutputStream out, Path file, long lastSeqZ) throws Exception {
        long size = Files.size(file);
        long seqB = lastSeqZ + 1;
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            byte[] block = new byte[BLOCK_SIZE];
            long remaining = size;
            while (remaining > 0) {
                int n = raf.read(block, 0, (int) Math.min(block.length, remaining));
                if (n < 0) break;
                byte[] chunk = (n == block.length) ? block : Arrays.copyOf(block, n);
                ProtocolMessage msg4 = ProtocolMessage.createType4(seqB, chunk, serverConfig);
                msg4.send(out);
                remaining -= n;
                seqB++;
            }
            ProtocolMessage msg5 = ProtocolMessage.createType5(seqB, "STREAM_FINISHED", serverConfig);
            msg5.send(out);
        }
    }
    static void sendErrorAndClose(OutputStream out, String reason) {
        try {
            System.err.println("Protocol error: " + reason);
            ProtocolMessage err = ProtocolMessage.createError(reason);
            err.send(out);
        } catch (IOException ignored) {}
    }
}
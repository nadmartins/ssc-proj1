package streamproxy;
import common.CryptoConfig;
import common.CryptoService;
import common.ProtocolMessage;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.Executors;

/**
 * Proxy implemented with raw sockets only (java.net.ServerSocket / Socket), no
 * com.sun.net.httpserver, no java.net.http.HttpClient, no external libraries.
 * Serves a small page at "/" and relays GET /video/<file> to the origin server,
 * forwarding the Range header and streaming the response body back block by
 * block (no whole-file buffering). Each browser connection handles one request,
 * then closes.
 *
 * Usage: java ProxySocketServer [port=8080] [originHost=localhost] [originPort=8081]
 */
public class ProxySocketServer {
    static final int BLOCK_SIZE = 1024;
    private static CryptoConfig proxyConfig;
    private static final SecureRandom RANDOM = new SecureRandom();
    static final String INDEX_HTML = """
            <!doctype html>
            <html><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
            <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
              <h1>MP4 streamed through a plain-socket proxy</h1>
              <p>File: <input id="f" value="sample.mp4">
                 <button onclick="load()">Load</button></p>
              <video id="v" controls preload="metadata" style="width:100%"></video>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
                  v.load();
                }
                load();
              </script>
            </body></html>
            """;
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        String originHost = args.length > 1 ? args[1] : "localhost";
        int originPort = args.length > 2 ? Integer.parseInt(args[2]) : 8081;
        String configFile = args.length > 3 ? args[3] : "proxycrypto.config";
        proxyConfig = CryptoConfig.load(configFile);
        System.out.println("Proxy on http://localhost:" + port + "/  ->  http://" + originHost + ":" + originPort);
        try (ServerSocket server = new ServerSocket(port)) {
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, originHost, originPort));
            }
        }
    }
    static void handle(Socket browser, String originHost, int originPort) {
        try (browser) {
            InputStream in = browser.getInputStream();
            OutputStream out = browser.getOutputStream();
            String requestLine = HttpUtil.readLine(in);
            if (requestLine == null || !requestLine.startsWith("GET ")) {
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }
            String path = requestLine.split(" ")[1];
            String line;
            while ((line = HttpUtil.readLine(in)) != null && !line.isEmpty()) {
                // Drain headers
            }
            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }
            if (!path.startsWith("/video/")) {
                writeSimpleStatus(out, 404, "Not Found");
                return;
            }
            String mediaName = path.substring("/video/".length());
            relaySecureStream(out, originHost, originPort, mediaName);
        } catch (IOException ignored) {
        }
    }
    static void servePage(OutputStream out) throws IOException {
        byte[] page = INDEX_HTML.getBytes(StandardCharsets.UTF_8);
        StringBuilder headers = new StringBuilder();
        headers.append("HTTP/1.1 200 OK\r\n")
                .append("Content-Type: text/html; charset=utf-8\r\n")
                .append("Content-Length: ").append(page.length).append("\r\n")
                .append("Connection: close\r\n\r\n");
        out.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(page);
        out.flush();
    }
    static void relaySecureStream(OutputStream browserOut, String originHost, int originPort, String mediaName) {
        long startTime = System.currentTimeMillis();
        long encryptedBlocksReceived = 0;
        long decryptedBlocksForwarded = 0;
        long totalBytesProcessed = 0;
        try (Socket origin = new Socket(originHost, originPort)) {
            OutputStream originOut = origin.getOutputStream();
            InputStream originIn = origin.getInputStream();
            long secX = RANDOM.nextLong() & 0x7FFFFFFFFFFFFFFFL;
            ProtocolMessage msg1 = ProtocolMessage.createType1(secX, proxyConfig.toPcc());
            msg1.send(originOut);
            ProtocolMessage msg2 = ProtocolMessage.read(originIn);
            if (msg2 == null || msg2.getType() != ProtocolMessage.TYPE_2_SERVER_CHALLENGE) {
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }
            ProtocolMessage.Type2Data type2 = msg2.parseType2(proxyConfig);
            if (type2.seqy() != secX + 1) {
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }
            byte[] responseR = CryptoService.sha256(type2.srv());
            long seqZ = type2.seqy() + 1;
            ProtocolMessage msg3 = ProtocolMessage.createType3(seqZ, responseR, mediaName, proxyConfig);
            msg3.send(originOut);
            String httpHeader = "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nConnection: close\r\n\r\n";
            browserOut.write(httpHeader.getBytes(StandardCharsets.US_ASCII));
            browserOut.flush();
            long expectedSeq = seqZ + 1;
            while (true) {
                ProtocolMessage streamMsg = ProtocolMessage.read(originIn);
                if (streamMsg == null) break;
                if (streamMsg.getType() == ProtocolMessage.TYPE_4_STREAM_BLOCK) {
                    encryptedBlocksReceived++;
                    ProtocolMessage.Type4Data type4 = streamMsg.parseType4(proxyConfig);
                    if (type4.seqb() != expectedSeq) {
                        break;
                    }
                    browserOut.write(type4.videoBlock());
                    browserOut.flush();
                    decryptedBlocksForwarded++;
                    totalBytesProcessed += type4.videoBlock().length;
                    expectedSeq++;
                } else if (streamMsg.getType() == ProtocolMessage.TYPE_5_STREAM_END) {
                    break;
                } else if (streamMsg.getType() == ProtocolMessage.TYPE_ERROR) {
                    break;
                }
            }
            printMetrics(encryptedBlocksReceived, decryptedBlocksForwarded, totalBytesProcessed, startTime);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
    private static void printMetrics(long received, long forwarded, long bytesProcessed, long startTime) {
        long durationMs = Math.max(1, System.currentTimeMillis() - startTime);
        double seconds = durationMs / 1000.0;
        double throughputKB = (bytesProcessed / 1024.0) / seconds;
        System.out.println("Number of encrypted blocks received: " + received);
        System.out.println("Number of decrypted blocks forwarded: " + forwarded);
        System.out.printf("Observed stream throughput: %.2f kB/s\n", throughputKB);
        System.out.println("Total volume of processed data: " + bytesProcessed + " bytes");
    }
    static void writeSimpleStatus(OutputStream out, int code, String reason) throws IOException {
        String resp = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
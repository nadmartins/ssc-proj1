package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ProtocolMessage {

    public static final byte TYPE_1_PROXY_PROPOSAL   = 1;
    public static final byte TYPE_2_SERVER_CHALLENGE = 2;
    public static final byte TYPE_3_PROXY_REQUEST    = 3;
    public static final byte TYPE_4_STREAM_BLOCK     = 4;
    public static final byte TYPE_5_STREAM_END       = 5;
    public static final byte TYPE_ERROR              = (byte) 255;

    public static final short CURRENT_VERSION = 1;
    public static final short CURRENT_RELEASE = 1;

    private final short version;
    private final short release;
    private final byte type;
    private final byte[] payload;

    public ProtocolMessage(byte type, byte[] payload) {
        this(CURRENT_VERSION, CURRENT_RELEASE, type, payload);
    }

    public ProtocolMessage(short version, short release, byte type, byte[] payload) {
        this.version = version;
        this.release = release;
        this.type = type;
        this.payload = (payload != null) ? payload : new byte[0];
    }

    // --- Envio e Leitura de Baixo Nivel pelo Socket ---

    public void send(OutputStream out) throws IOException {
        DataOutputStream dos = new DataOutputStream(out);
        dos.writeShort(version);
        dos.writeShort(release);
        dos.writeByte(type);
        dos.writeInt(payload.length);
        if (payload.length > 0) {
            dos.write(payload);
        }
        dos.flush();
    }

    public static ProtocolMessage read(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        short ver;
        try {
            ver = dis.readShort();
        } catch (IOException e) {
            return null;
        }
        short rel = dis.readShort();
        byte type = dis.readByte();
        int payloadLen = dis.readInt();

        /*if (payloadLen < 0 || payloadLen > 10 * 1024 * 1024) {
            throw new IOException("Invalid payload size: " + payloadLen);
        }*/

        byte[] payload = new byte[payloadLen];
        dis.readFully(payload);
        return new ProtocolMessage(ver, rel, type, payload);
    }


    public record Type1Data(long secx, String pcc) {}
    public record Type2Data(long seqy, byte[] srv, String ccc) {}
    public record Type3Data(long seqz, byte[] r, String media) {}
    public record Type4Data(long seqb, byte[] videoBlock) {}
    public record Type5Data(long seqf, String endSignal, String randomStr) {}
    public record ErrorData(String errorMessage) {}

    public static ProtocolMessage createType1(long secx, String pcc) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(secx);
        dos.writeUTF(pcc);
        return new ProtocolMessage(TYPE_1_PROXY_PROPOSAL, baos.toByteArray());
    }

    public static ProtocolMessage createType2(long seqy, byte[] srv, String ccc, CryptoConfig config) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(seqy);
        dos.writeInt(srv.length);
        dos.write(srv);
        dos.writeUTF(ccc);
        byte[] ciphertext = CryptoService.encrypt(baos.toByteArray(), config);
        return new ProtocolMessage(TYPE_2_SERVER_CHALLENGE, ciphertext);
    }

    public static ProtocolMessage createType3(long seqz, byte[] r, String media, CryptoConfig config) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(seqz);
        dos.writeInt(r.length);
        dos.write(r);
        dos.writeUTF(media);
        byte[] ciphertext = CryptoService.encrypt(baos.toByteArray(), config);
        return new ProtocolMessage(TYPE_3_PROXY_REQUEST, ciphertext);
    }

    public static ProtocolMessage createType4(long seqb, byte[] videoBlock, CryptoConfig config) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(seqb);
        dos.writeInt(videoBlock.length);
        dos.write(videoBlock);
        byte[] ciphertext = CryptoService.encrypt(baos.toByteArray(), config);
        return new ProtocolMessage(TYPE_4_STREAM_BLOCK, ciphertext);
    }

    public static ProtocolMessage createType5(long seqf, String randomStr, CryptoConfig config) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeLong(seqf);
        dos.writeUTF("END");
        dos.writeUTF(randomStr != null ? randomStr : "FINISHED");
        byte[] ciphertext = CryptoService.encrypt(baos.toByteArray(), config);
        return new ProtocolMessage(TYPE_5_STREAM_END, ciphertext);
    }

    public static ProtocolMessage createError(String errorMessage) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeUTF(errorMessage != null ? errorMessage : "Unknown error");
        return new ProtocolMessage(TYPE_ERROR, baos.toByteArray());
    }

    public Type1Data parseType1() throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(this.payload));
        long secx = dis.readLong();
        String pcc = dis.readUTF();
        return new Type1Data(secx, pcc);
    }

    public Type2Data parseType2(CryptoConfig config) throws Exception {
        byte[] plaintext = CryptoService.decrypt(this.payload, config);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plaintext));
        long seqy = dis.readLong();
        int srvLen = dis.readInt();
        byte[] srv = new byte[srvLen];
        dis.readFully(srv);
        String ccc = dis.readUTF();
        return new Type2Data(seqy, srv, ccc);
    }

    public Type3Data parseType3(CryptoConfig config) throws Exception {
        byte[] plaintext = CryptoService.decrypt(this.payload, config);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plaintext));
        long seqz = dis.readLong();
        int rLen = dis.readInt();
        byte[] r = new byte[rLen];
        dis.readFully(r);
        String media = dis.readUTF();
        return new Type3Data(seqz, r, media);
    }

    public Type4Data parseType4(CryptoConfig config) throws Exception {
        byte[] plaintext = CryptoService.decrypt(this.payload, config);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plaintext));
        long seqb = dis.readLong();
        int blockLen = dis.readInt();
        byte[] videoBlock = new byte[blockLen];
        dis.readFully(videoBlock);
        return new Type4Data(seqb, videoBlock);
    }

    public Type5Data parseType5(CryptoConfig config) throws Exception {
        byte[] plaintext = CryptoService.decrypt(this.payload, config);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plaintext));
        long seqf = dis.readLong();
        String end = dis.readUTF();
        String randomStr = dis.readUTF();
        return new Type5Data(seqf, end, randomStr);
    }

    public ErrorData parseError() throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(this.payload));
        return new ErrorData(dis.readUTF());
    }

    // Getters
    public short getVersion() { return version; }
    public short getRelease() { return release; }
    public byte getType() { return type; }
    public byte[] getPayload() { return payload; }
}
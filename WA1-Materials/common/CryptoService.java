package common;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoService {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int AEAD_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public static byte[] encrypt(byte[] plaintext, CryptoConfig config) throws Exception {
        if (config.isAead()) {
            return encryptAead(plaintext, config);
        } else {
            return encryptClassic(plaintext, config);
        }
    }

    public static byte[] decrypt(byte[] encryptedData, CryptoConfig config) throws Exception {
        if (config.isAead()) {
            return decryptAead(encryptedData, config);
        } else {
            return decryptClassic(encryptedData, config);
        }
    }

    //AEAD Modes (AES/GCM, ChaCha20-Poly1305, AES/CCM)
    private static byte[] encryptAead(byte[] plaintext, CryptoConfig config) throws Exception {
        byte[] nonce = generateNonce(AEAD_NONCE_LENGTH);
        Cipher cipher = Cipher.getInstance(config.getTransformation());

        if (config.getMode().equalsIgnoreCase("GCM")) {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        ByteBuffer bb = ByteBuffer.allocate(nonce.length + ciphertext.length);
        bb.put(nonce);
        bb.put(ciphertext);
        return bb.array();
    }

    private static byte[] decryptAead(byte[] encryptedData, CryptoConfig config) throws Exception {
        if (encryptedData.length < AEAD_NONCE_LENGTH) {
            throw new IllegalArgumentException("Encrypted payload shorter than nonce length.");
        }

        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, AEAD_NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, AEAD_NONCE_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance(config.getTransformation());
        if (config.getMode().equalsIgnoreCase("GCM")) {
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
        }

        return cipher.doFinal(ciphertext);
    }

    //Classic Modes (CBC, CTR with IV; ECB without IV) + Optional HMAC
    private static byte[] encryptClassic(byte[] plaintext, CryptoConfig config) throws Exception {
        boolean isEcb = "ECB".equalsIgnoreCase(config.getMode());
        boolean hasMac = !config.getMacAlgorithm().equalsIgnoreCase("NULL");

        Cipher cipher = Cipher.getInstance(config.getTransformation());
        byte[] iv = null;

        if (isEcb) {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey());
        } else {
            int ivSize = (config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16;
            iv = generateNonce(ivSize);
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        if (hasMac) {
            Mac mac = Mac.getInstance(config.getMacAlgorithm());
            mac.init(config.getMacKey());
            if (iv != null) {
                mac.update(iv);
            }
            byte[] hmacTag = mac.doFinal(ciphertext);

            int totalSize = (iv != null ? iv.length : 0) + ciphertext.length + hmacTag.length;
            ByteBuffer bb = ByteBuffer.allocate(totalSize);
            if (iv != null) bb.put(iv);
            bb.put(ciphertext);
            bb.put(hmacTag);
            return bb.array();
        } else {
            int totalSize = (iv != null ? iv.length : 0) + ciphertext.length;
            ByteBuffer bb = ByteBuffer.allocate(totalSize);
            if (iv != null) bb.put(iv);
            bb.put(ciphertext);
            return bb.array();
        }
    }

    private static byte[] decryptClassic(byte[] encryptedData, CryptoConfig config) throws Exception {
        boolean isEcb = "ECB".equalsIgnoreCase(config.getMode());
        boolean hasMac = !config.getMacAlgorithm().equalsIgnoreCase("NULL");

        int ivSize = isEcb ? 0 : ((config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16);
        int macSize = 0;

        if (hasMac) {
            Mac testMac = Mac.getInstance(config.getMacAlgorithm());
            macSize = testMac.getMacLength();
        }

        if (encryptedData.length < ivSize + macSize) {
            throw new IllegalArgumentException("Encrypted payload truncated or invalid.");
        }

        byte[] iv = isEcb ? null : Arrays.copyOfRange(encryptedData, 0, ivSize);
        int ciphertextEnd = encryptedData.length - macSize;
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, ivSize, ciphertextEnd);

        if (hasMac) {
            byte[] receivedMac = Arrays.copyOfRange(encryptedData, ciphertextEnd, encryptedData.length);
            Mac mac = Mac.getInstance(config.getMacAlgorithm());
            mac.init(config.getMacKey());
            if (iv != null) {
                mac.update(iv);
            }
            byte[] expectedMac = mac.doFinal(ciphertext);

            if (!MessageDigest.isEqual(expectedMac, receivedMac)) {
                throw new SecurityException("Integrity check failed: invalid HMAC! Message has been tampered with.");
            }
        }

        Cipher cipher = Cipher.getInstance(config.getTransformation());
        if (isEcb) {
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey());
        } else {
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
        }

        return cipher.doFinal(ciphertext);
    }


    public static byte[] generateNonce(int length) {
        byte[] nonce = new byte[length];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
package common;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Servico central de operacoes criptograficas (Cifragem, Decifragem, Hashes e Nonces)
 * em conformidade com as seccoes 2.2.3 e 2.2.4 do enunciado e os Labs 3.1 e 3.2.
 */
public class CryptoService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int AEAD_NONCE_LENGTH = 12; // 12 bytes = 96 bits (GCM e ChaCha20-Poly1305)
    private static final int GCM_TAG_LENGTH = 128;   // 128 bits de tag de autenticacao

    /**
     * Cifra os dados de acordo com a configuracao (AEAD ou Bloco+HMAC).
     */
    public static byte[] encrypt(byte[] plaintext, CryptoConfig config) throws Exception {
        if (config.isAead()) {
            return encryptAead(plaintext, config);
        } else {
            return encryptClassic(plaintext, config);
        }
    }

    /**
     * Decifra os dados e verifica a autenticidade/integridade.
     */
    public static byte[] decrypt(byte[] encryptedData, CryptoConfig config) throws Exception {
        if (config.isAead()) {
            return decryptAead(encryptedData, config);
        } else {
            return decryptClassic(encryptedData, config);
        }
    }

    // --- Cifragem e Decifragem AEAD (AES-GCM / ChaCha20-Poly1305) ---

    private static byte[] encryptAead(byte[] plaintext, CryptoConfig config) throws Exception {
        byte[] nonce = generateNonce(AEAD_NONCE_LENGTH);
        Cipher cipher = Cipher.getInstance(config.getTransformation());

        if (config.getMode().equalsIgnoreCase("GCM")) {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Formato final: Nonce (12 bytes) || Ciphertext (inclui tag AEAD)
        ByteBuffer bb = ByteBuffer.allocate(nonce.length + ciphertext.length);
        bb.put(nonce);
        bb.put(ciphertext);
        return bb.array();
    }

    private static byte[] decryptAead(byte[] encryptedData, CryptoConfig config) throws Exception {
        if (encryptedData.length < AEAD_NONCE_LENGTH) {
            throw new IllegalArgumentException("Dados cifrados menores que o tamanho do Nonce.");
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

    // --- Cifragem e Decifragem Classica (ex: CBC/CTR + HMAC) ---

    private static byte[] encryptClassic(byte[] plaintext, CryptoConfig config) throws Exception {
        int ivSize = (config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16;
        byte[] iv = generateNonce(ivSize);

        Cipher cipher = Cipher.getInstance(config.getTransformation());
        cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Se estiver configurado um MACSuite (HMAC)
        if (!config.getMacAlgorithm().equalsIgnoreCase("NULL")) {
            Mac mac = Mac.getInstance(config.getMacAlgorithm());
            mac.init(config.getMacKey());
            // Calcula HMAC sobre IV || Ciphertext (Encrypt-then-MAC)
            mac.update(iv);
            byte[] hmacTag = mac.doFinal(ciphertext);

            ByteBuffer bb = ByteBuffer.allocate(iv.length + ciphertext.length + hmacTag.length);
            bb.put(iv);
            bb.put(ciphertext);
            bb.put(hmacTag);
            return bb.array();
        } else {
            // Sem MAC (apenas IV || Ciphertext)
            ByteBuffer bb = ByteBuffer.allocate(iv.length + ciphertext.length);
            bb.put(iv);
            bb.put(ciphertext);
            return bb.array();
        }
    }

    private static byte[] decryptClassic(byte[] encryptedData, CryptoConfig config) throws Exception {
        int ivSize = (config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16;
        boolean hasMac = !config.getMacAlgorithm().equalsIgnoreCase("NULL");

        int macSize = 0;
        if (hasMac) {
            Mac testMac = Mac.getInstance(config.getMacAlgorithm());
            macSize = testMac.getMacLength();
        }

        if (encryptedData.length < ivSize + macSize) {
            throw new IllegalArgumentException("Dados cifrados truncados ou invalidos.");
        }

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, ivSize);
        int ciphertextEnd = encryptedData.length - macSize;
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, ivSize, ciphertextEnd);

        // Se houver HMAC, verificar obrigatoriamente antes de decifrar
        if (hasMac) {
            byte[] receivedMac = Arrays.copyOfRange(encryptedData, ciphertextEnd, encryptedData.length);
            Mac mac = Mac.getInstance(config.getMacAlgorithm());
            mac.init(config.getMacKey());
            mac.update(iv);
            byte[] expectedMac = mac.doFinal(ciphertext);

            // Comparacao em tempo constante (como visto em HmacExample.java)
            if (!MessageDigest.isEqual(expectedMac, receivedMac)) {
                throw new SecurityException("Falha de integridade: HMAC invalido! Mensagem adulterada.");
            }
        }

        Cipher cipher = Cipher.getInstance(config.getTransformation());
        cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    // --- Metodos Auxiliares de Seguranca ---

    /**
     * Gera um array de bytes criptograficamente aleatorios (Nonce / Challenge / IV).
     */
    public static byte[] generateNonce(int length) {
        byte[] nonce = new byte[length];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    /**
     * Calcula o hash SHA-256 de dados (ex: R = SHA-256(SRV) na mensagem Tipo 3).
     */
    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}

package common;

import java.io.File;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;


public class CryptoConfig {

    private final String algorithm;
    private final String mode;
    private final String ivValue;
    private final int ivSize;
    private final String padding;
    private final String macAlgorithm;
    private final byte[] secretKeyBytes;
    private final int keySize;
    private final byte[] macKeyBytes;
    private final int macKeySize;

    public CryptoConfig(String algorithm, String mode, String ivValue, int ivSize, String padding,
                        String macAlgorithm, byte[] secretKeyBytes, int keySize,
                        byte[] macKeyBytes, int macKeySize) {
        this.algorithm = algorithm;
        this.mode = mode;
        this.ivValue = ivValue;
        this.ivSize = ivSize;
        this.padding = padding;
        this.macAlgorithm = macAlgorithm;
        this.secretKeyBytes = secretKeyBytes;
        this.keySize = keySize;
        this.macKeyBytes = macKeyBytes;
        this.macKeySize = macKeySize;
    }


    public static CryptoConfig load(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("Config File not found: " + filePath);
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(file);
        doc.getDocumentElement().normalize();

        String algorithm = getTagValue(doc, "Algorithm");
        String mode = getTagValue(doc, "Mode");
        String ivValue = getTagValue(doc, "IV");
        String ivSizeStr = getTagValue(doc, "IVSize");
        int ivSize = (ivSizeStr != null && !ivSizeStr.equalsIgnoreCase("NULL")) ? Integer.parseInt(ivSizeStr) : 0;
        String padding = getTagValue(doc, "Padding");

        String macAlgorithm = "NULL";
        NodeList macSuites = doc.getElementsByTagName("MACSuite");
        if (macSuites.getLength() > 0) {
            Element macEl = (Element) macSuites.item(0);
            NodeList algList = macEl.getElementsByTagName("Algorithm");
            if (algList.getLength() > 0) {
                macAlgorithm = algList.item(0).getTextContent().trim();
            }
        }

        String sKeyHex = getTagValue(doc, "SKey");
        String keySizeStr = getTagValue(doc, "KeySize");
        int keySize = (keySizeStr != null && !keySizeStr.equalsIgnoreCase("NULL")) ? Integer.parseInt(keySizeStr) : 0;
        byte[] secretKeyBytes = parseHexKey(sKeyHex);

        String macKeyHex = getTagValue(doc, "MacKey");
        String macKeySizeStr = getTagValue(doc, "MacKeySize");
        int macKeySize = (macKeySizeStr != null && !macKeySizeStr.equalsIgnoreCase("NULL")) ? Integer.parseInt(macKeySizeStr) : 0;
        byte[] macKeyBytes = parseHexKey(macKeyHex);

        return new CryptoConfig(algorithm, mode, ivValue, ivSize, padding,
                macAlgorithm, secretKeyBytes, keySize, macKeyBytes, macKeySize);
    }

    private static String getTagValue(Document doc, String tagName) {
        NodeList list = doc.getElementsByTagName(tagName);
        if (list.getLength() > 0 && list.item(0).getTextContent() != null) {
            return list.item(0).getTextContent().trim();
        }
        return "NULL";
    }

    private static byte[] parseHexKey(String hex) {
        if (hex == null || hex.equalsIgnoreCase("NULL") || hex.isBlank()) {
            return null;
        }
        String cleanHex = hex.replaceAll("\\s+", "");
        return HexFormat.of().parseHex(cleanHex);
    }


    public String toPcc() {
        return algorithm + "/" + mode + "/" + ivValue + "/" + padding;
    }


    public String getTransformation() {
        String pad = (padding == null || padding.equalsIgnoreCase("NULL")) ? "NoPadding" : padding;
        return algorithm + "/" + mode + "/" + pad;
    }


    public boolean isAead() {
        return "GCM".equalsIgnoreCase(mode) || "CCM".equalsIgnoreCase(mode) || "ChaCha20-Poly1305".equalsIgnoreCase(algorithm);
    }

    public SecretKey getSecretKey() {
        if (secretKeyBytes == null) return null;
        return new SecretKeySpec(secretKeyBytes, algorithm);
    }

    public SecretKey getMacKey() {
        if (macKeyBytes == null) return null;
        return new SecretKeySpec(macKeyBytes, macAlgorithm);
    }


    public boolean isCompatibleWith(CryptoConfig other) {
        if (other == null) return false;
        return this.algorithm.equalsIgnoreCase(other.getAlgorithm())
                && this.mode.equalsIgnoreCase(other.getMode())
                && this.keySize == other.getKeySize()
                && this.padding.equalsIgnoreCase(other.getPadding())
                && this.macAlgorithm.equalsIgnoreCase(other.getMacAlgorithm());
    }

    // Getters
    public String getAlgorithm() { return algorithm; }
    public String getMode() { return mode; }
    public String getIvValue() { return ivValue; }
    public int getIvSize() { return ivSize; }
    public String getPadding() { return padding; }
    public String getMacAlgorithm() { return macAlgorithm; }
    public int getKeySize() { return keySize; }
    public byte[] getSecretKeyBytes() { return secretKeyBytes; }
    public byte[] getMacKeyBytes() { return macKeyBytes; }
}

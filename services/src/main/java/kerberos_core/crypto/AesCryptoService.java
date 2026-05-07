package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * Implementation of CryptoOperations using Standard Java Cryptography
 * for AES-256-CBC, HMAC-SHA256, and PBKDF2-HMAC-SHA256 key derivation.
 */
public class AesCryptoService implements CryptoOperations {

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 16; // AES block size is 128 bits (16 bytes)
    private static final int SALT_SIZE = 16;
    private static final int KDF_ITERATIONS = 310_000; // OWASP recommended minimum
    private static final int DERIVED_KEY_LENGTH = 256; // bits

    private final SecureRandom secureRandom;

    public AesCryptoService() {
        this.secureRandom = new SecureRandom();
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(encryptedData);
    }

    @Override
    public byte[] generateHmac(byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    @Override
    public long generateNonce() {
        return secureRandom.nextLong();
    }

    @Override
    public byte[] generateSessionKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(AES_KEY_SIZE, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    @Override
    public byte[] generateIv() {
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        return iv;
    }

    @Override
    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        secureRandom.nextBytes(salt);
        return salt;
    }

    @Override
    public byte[] deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, KDF_ITERATIONS, DERIVED_KEY_LENGTH);
        SecretKey derived = factory.generateSecret(spec);
        return derived.getEncoded();
    }

    @Override
    public boolean verifyPassword(String password, String storedHash, String salt) throws Exception {
        byte[] saltBytes = Base64.getDecoder().decode(salt);
        byte[] derivedKey = deriveKey(password, saltBytes);
        byte[] storedKey = Base64.getDecoder().decode(storedHash);
        // Constant-time comparison to prevent timing attacks
        return MessageDigest.isEqual(derivedKey, storedKey);
    }
}

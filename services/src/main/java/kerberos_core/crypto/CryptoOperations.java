package crypto;

/**
 * Interface defining required cryptographic operations for the Kerberos protocol.
 * Using OOP concepts by abstracting the cryptography implementation.
 */
public interface CryptoOperations {
    
    /**
     * Encrypts data using the specified key and initialization vector.
     */
    byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws Exception;
    
    /**
     * Decrypts data using the specified key and initialization vector.
     */
    byte[] decrypt(byte[] encryptedData, byte[] key, byte[] iv) throws Exception;
    
    /**
     * Generates an HMAC-SHA256 signature for the given data.
     */
    byte[] generateHmac(byte[] data, byte[] key) throws Exception;
    
    /**
     * Generates a random nonce to prevent replay attacks.
     */
    long generateNonce();
    
    /**
     * Generates a secure session key (AES-256).
     */
    byte[] generateSessionKey() throws Exception;

    /**
     * Generates a random Initialization Vector (IV) for AES CBC.
     */
    byte[] generateIv();

    /**
     * Generates a cryptographically secure random salt for password hashing.
     *
     * @return a 16-byte random salt
     */
    byte[] generateSalt();

    /**
     * Derives a 256-bit AES key from a plaintext password and salt using PBKDF2.
     * This is used to convert a user's password into their Kerberos long-term key.
     *
     * @param password the plaintext password
     * @param salt     the random salt
     * @return 32-byte derived key suitable for AES-256
     */
    byte[] deriveKey(String password, byte[] salt) throws Exception;

    /**
     * Verifies that a plaintext password matches a stored hash by re-deriving
     * the key with the provided salt and comparing the results.
     *
     * @param password   the plaintext password to verify
     * @param storedHash the previously stored derived key (Base64-encoded)
     * @param salt       the salt used during the original derivation (Base64-encoded)
     * @return true if the password matches, false otherwise
     */
    boolean verifyPassword(String password, String storedHash, String salt) throws Exception;
}

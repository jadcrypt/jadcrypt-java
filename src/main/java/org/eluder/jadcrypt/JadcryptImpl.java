package org.eluder.jadcrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JadcryptImpl implements Jadcrypt {

    public static final String DEFAULT_ALGORITHM = "AES";
    public static final String DEFAULT_CIPHER = DEFAULT_ALGORITHM + "/CBC/PKCS5Padding";

    private final String algorithm;
    private final String cipher;

    public JadcryptImpl() {
        this(DEFAULT_ALGORITHM, DEFAULT_CIPHER);
    }

    public JadcryptImpl(String algorithm, String cipher) {
        this.algorithm = algorithm;
        this.cipher = cipher;
    }

    @Override
    public String encrypt(String plain, String password, String salt) {
        return encrypt(plain, password, salt, Encoding.HEX, Presets.DEFAULTS);
    }

    @Override
    public String encrypt(String plain, String password, String salt, Encoding encoding) {
        return encrypt(plain, password, salt, encoding, Presets.DEFAULTS);
    }

    @Override
    public String encrypt(String plain, String password, String salt, Encoding encoding, Presets presets) {
        byte[] key = CryptUtils.pbkdf2(password, salt, presets);
        byte[] iv = CryptUtils.md5(salt);

        return encoding.encode(encryptRaw(plain.getBytes(Presets.CHARSET), key, iv));
    }

    @Override
    public byte[] encryptRaw(byte[] plain, byte[] key, byte[] iv) {
        SecretKey secret = new SecretKeySpec(key, this.algorithm);
        IvParameterSpec ips = new IvParameterSpec(iv);

        try {
            Cipher cipher = Cipher.getInstance(this.cipher);
            cipher.init(Cipher.ENCRYPT_MODE, secret, ips);
            return cipher.doFinal(plain);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new IllegalStateException(ex);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    @Override
    public String decrypt(String encrypted, String password, String salt) {
        return decrypt(encrypted, password, salt, Encoding.HEX, Presets.DEFAULTS);
    }

    @Override
    public String decrypt(String encrypted, String password, String salt, Encoding encoding) {
        return decrypt(encrypted, password, salt, encoding, Presets.DEFAULTS);
    }

    @Override
    public String decrypt(String encrypted, String password, String salt, Encoding encoding, Presets presets) {
        byte[] key = CryptUtils.pbkdf2(password, salt, presets);
        byte[] iv = CryptUtils.md5(salt);

        return new String(decryptRaw(encoding.decode(encrypted), key, iv), Presets.CHARSET);
    }

    @Override
    public byte[] decryptRaw(byte[] encrypted, byte[] key, byte[] iv) {
        SecretKey secret = new SecretKeySpec(key, this.algorithm);
        IvParameterSpec ips = new IvParameterSpec(iv);

        try {
            Cipher cipher = Cipher.getInstance(this.cipher);
            cipher.init(Cipher.DECRYPT_MODE, secret, ips);
            return cipher.doFinal(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new IllegalStateException(ex);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

}

package org.eluder.jadcrypt;

import org.junit.Test;

import static org.junit.Assert.*;

public class JadcryptImplTest {

    final Jadcrypt jadcrypt = new JadcryptImpl();

    final String message = "Hello wörld!";
    final String password = "l5681mm0Yfi486y";
    final String salt = "cjttN5DS";

    final byte[] rawMessage = message.getBytes(Presets.CHARSET);
    final byte[] key = CryptUtils.random(256);
    final byte[] iv = CryptUtils.random(128);

    @Test
    public void testEncryptAndDecryptWithDefaults() throws Exception {
        String encrypted = jadcrypt.encrypt(message, password, salt);
        String decrypted = jadcrypt.decrypt(encrypted, password, salt);

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithBase64AndSimplePresets() throws Exception {
        String encrypted = jadcrypt.encrypt(message, password, salt, Encoding.BASE64, Presets.SIMPLE);
        String decrypted = jadcrypt.decrypt(encrypted, password, salt, Encoding.BASE64, Presets.SIMPLE);

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncodingsAreDifferent() throws Exception {
        String encrypted1 = jadcrypt.encrypt(message, password, salt, Encoding.HEX);
        String encrypted2 = jadcrypt.encrypt(message, password, salt, Encoding.BASE64);

        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    public void testPresetsAreDifferent() throws Exception {
        String encrypted1 = jadcrypt.encrypt(message, password, salt, Encoding.HEX, Presets.DEFAULTS);
        String encrypted2 = jadcrypt.encrypt(message, password, salt, Encoding.HEX, Presets.SIMPLE);

        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    public void testEncryptRawAndDecryptRaw() throws Exception {
        byte[] encrypted = jadcrypt.encryptRaw(rawMessage, key, iv);
        byte[] decrypted = jadcrypt.decryptRaw(encrypted, key, iv);

        assertArrayEquals(rawMessage, decrypted);
    }
}

package org.eluder.jadcrypt;

import org.junit.Test;

import static org.junit.Assert.*;

public class JadcryptImplTest {

    final String message = "Hello wörld!";
    final String password = "l5681mm0Yfi486y";
    final String salt = "cjttN5DS";

    final byte[] rawMessage = message.getBytes(Presets.CHARSET);
    final byte[] key = CryptUtils.random(256);
    final byte[] iv = CryptUtils.random(128);

    @Test
    public void testEncryptAndDecryptWithDefaults() throws Exception {
        Jadcrypt jadcrypt = new JadcryptImpl();
        String encrypted = jadcrypt.encrypt(message, password, salt);
        String decrypted = jadcrypt.decrypt(encrypted, password, salt);

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptAndDecryptWithBase64AndSimplePresets() throws Exception {
        Jadcrypt jadcrypt = new JadcryptImpl(Encoding.BASE64, Presets.SIMPLE);
        String encrypted = jadcrypt.encrypt(message, password, salt);
        String decrypted = jadcrypt.decrypt(encrypted, password, salt);

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncodingsAreDifferent() throws Exception {
        Jadcrypt jadcrypt1 = new JadcryptImpl(Encoding.HEX, Presets.DEFAULTS);
        Jadcrypt jadcrypt2 = new JadcryptImpl(Encoding.BASE64, Presets.DEFAULTS);
        String encrypted1 = jadcrypt1.encrypt(message, password, salt);
        String encrypted2 = jadcrypt2.encrypt(message, password, salt);

        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    public void testPresetsAreDifferent() throws Exception {
        Jadcrypt jadcrypt1 = new JadcryptImpl(Encoding.HEX, Presets.DEFAULTS);
        Jadcrypt jadcrypt2 = new JadcryptImpl(Encoding.HEX, Presets.SIMPLE);
        String encrypted1 = jadcrypt1.encrypt(message, password, salt);
        String encrypted2 = jadcrypt2.encrypt(message, password, salt);

        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    public void testEncryptRawAndDecryptRaw() throws Exception {
        Jadcrypt jadcrypt = new JadcryptImpl();
        byte[] encrypted = jadcrypt.encryptRaw(rawMessage, key, iv);
        byte[] decrypted = jadcrypt.decryptRaw(encrypted, key, iv);

        assertArrayEquals(rawMessage, decrypted);
    }
}

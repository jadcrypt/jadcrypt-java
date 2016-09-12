package org.eluder.jadcrypt;

public interface Jadcrypt {

    String encrypt(String plain, String password, String salt);

    String encrypt(String plain, String password, String salt, Encoding encoding);

    String encrypt(String plain, String password, String salt, Encoding encoding, Presets presets);

    byte[] encryptRaw(byte[] plain, byte[] key, byte[] iv);

    String decrypt(String encrypted, String password, String salt);

    String decrypt(String encrypted, String password, String salt, Encoding encoding);

    String decrypt(String encrypted, String password, String salt, Encoding encoding, Presets presets);

    byte[] decryptRaw(byte[] encrypted, byte[] key, byte[] iv);

}

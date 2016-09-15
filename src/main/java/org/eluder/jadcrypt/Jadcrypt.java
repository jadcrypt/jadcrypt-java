package org.eluder.jadcrypt;

public interface Jadcrypt {

    String encrypt(String plain, String password, String salt);

    byte[] encryptRaw(byte[] plain, byte[] key, byte[] iv);

    String decrypt(String encrypted, String password, String salt);

    byte[] decryptRaw(byte[] encrypted, byte[] key, byte[] iv);

}

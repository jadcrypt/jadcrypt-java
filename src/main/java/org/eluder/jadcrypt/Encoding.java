package org.eluder.jadcrypt;

import java.util.function.Function;

public enum Encoding {

    HEX(CryptUtils::toHex, CryptUtils::fromHex),
    BASE64(CryptUtils::toBase64, CryptUtils::fromBase64);

    private final Function<byte[], String> encoder;
    private final Function<String, byte[]> decoder;

    Encoding(Function<byte[], String> encoder, Function<String, byte[]> decoder) {
        this.encoder = encoder;
        this.decoder = decoder;
    }

    public String encode(byte[] raw) {
        return encoder.apply(raw);
    }

    public byte[] decode(String encoded) {
        return decoder.apply(encoded);
    }

}

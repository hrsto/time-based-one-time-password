package com.webarity.auth.support;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * <p>Encodes arbitrary byte arrays as case-insensitive base-32 strings.</p>
 * <p>Taken from Google Authenticator github. See below links for description.</p>
 * 
 * @see <a href="https://github.com/google/google-authenticator-android/blob/master/java/com/google/android/apps/authenticator/util/Base32String.java" target="_blank">Base32String</a>
 * @see <a href="https://github.com/google/google-authenticator-android" target="_blank">Google Authenticator</a>
 */
public class Base32String {

    private static final String SEPARATOR = "-";
    private static final char[] DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int MASK = DIGITS.length - 1;
    private static final int SHIFT = Integer.numberOfTrailingZeros(DIGITS.length);
    private static final Map<Character, Integer> CHAR_MAP = new HashMap<>(DIGITS.length);

    static {
        for (int i = 0; i < DIGITS.length; i++) {
            CHAR_MAP.put(DIGITS[i], i);
        }
    }

    /**
     * <p>Decode an encoded String.</p>
     * 
     * @param encoded encoded String
     * @return decoded String
     */
    public static byte[] decode(String encoded) {
        // Remove whitespace and separators
        encoded = encoded.trim().replaceAll(SEPARATOR, "").replaceAll(" ", "");

        // Remove padding. Note: the padding is used as hint to determine how many
        // bits to decode from the last incomplete chunk (which is commented out
        // below, so this may have been wrong to start with).
        encoded = encoded.replaceFirst("[=]*$", "");

        // Canonicalize to all upper case
        encoded = encoded.toUpperCase(Locale.US);
        if (encoded.length() == 0) {
            return new byte[0];
        }
        int encodedLength = encoded.length();
        int outLength = encodedLength * SHIFT / 8;
        byte[] result = new byte[outLength];
        int buffer = 0;
        int next = 0;
        int bitsLeft = 0;
        for (char c : encoded.toCharArray()) {
            if (!CHAR_MAP.containsKey(c)) {
                throw new RuntimeException("Illegal character: " + c);
            }
            buffer <<= SHIFT;
            buffer |= CHAR_MAP.get(c) & MASK;
            bitsLeft += SHIFT;
            if (bitsLeft >= 8) {
                result[next++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        return result;
    }

    /**
     * <p>Encode a String.</p>
     * 
     * @param data byte representation of a String to encode
     * @return encoded String
     */
    public static String encode(byte[] data) {
        int dataLength = data.length;
        if (dataLength == 0) {
            return "";
        }

        // SHIFT is the number of bits per output character, so the length of the
        // output is the length of the input multiplied by 8/SHIFT, rounded up.
        if (dataLength >= (1 << 28)) {
            // The computation below will fail, so don't do it.
            throw new IllegalArgumentException();
        }

        int outputLength = (dataLength * 8 + SHIFT - 1) / SHIFT;
        StringBuilder result = new StringBuilder(outputLength);

        int buffer = data[0];
        int next = 1;
        int bitsLeft = 8;
        while (bitsLeft > 0 || next < dataLength) {
            if (bitsLeft < SHIFT) {
                if (next < dataLength) {
                    buffer <<= 8;
                    buffer |= (data[next++] & 0xff);
                    bitsLeft += 8;
                } else {
                    int pad = SHIFT - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            int index = MASK & (buffer >> (bitsLeft - SHIFT));
            bitsLeft -= SHIFT;
            result.append(DIGITS[index]);
        }
        return result.toString();
    }
}
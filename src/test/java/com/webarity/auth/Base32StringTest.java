package com.webarity.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import com.webarity.auth.support.Base32String;

import org.junit.jupiter.api.Test;

/**
 * <p>Tests adapted form Google Authenticator. See below link.</p>
 * 
 * @see <a href="https://github.com/google/google-authenticator-android/blob/master/javatests/com/google/android/apps/authenticator/util/Base32StringTest.java" target="_blank">Base32StringTest</a>
 */
public class Base32StringTest {

    private static final byte[] INPUT1 = "foo".getBytes();
    private static final byte[] INPUT2 = "foob".getBytes();
    private static final byte[] INPUT3 = "fooba".getBytes();
    private static final byte[] INPUT4 = "foobar".getBytes();

    private static final String OUTPUT1 = "MZXW6";
    private static final String OUTPUT2 = "MZXW6YQ";
    private static final String OUTPUT3 = "MZXW6YTB";
    private static final String OUTPUT4 = "MZXW6YTBOI";
    
    @Test
    public void testEncodingDecoding() {
        assertEquals(Base32String.encode(INPUT1), OUTPUT1);
        assertEquals(Base32String.encode(INPUT2), OUTPUT2);
        assertEquals(Base32String.encode(INPUT3), OUTPUT3);
        assertEquals(Base32String.encode(INPUT4), OUTPUT4);

        // check decoding
        assertTrue(() -> Arrays.equals(Base32String.decode(OUTPUT1), INPUT1));
        assertTrue(() -> Arrays.equals(Base32String.decode(OUTPUT2), INPUT2));
        assertTrue(() -> Arrays.equals(Base32String.decode(OUTPUT3), INPUT3));
        assertTrue(() -> Arrays.equals(Base32String.decode(OUTPUT4), INPUT4));

        byte[] b16 = Base32String.decode("7777777777777777"); // 16 7s.
        byte[] b17 = Base32String.decode("77777777777777777"); // 17 7s.
        assertTrue(() -> Arrays.equals(b16, b17));
    }

    @Test
    public void testMisc() {
        // decoded, but not enough to return any bytes.
        assertEquals(Base32String.decode("A").length, 0);
        assertEquals(Base32String.decode("").length, 0);
        assertEquals(Base32String.decode(" ").length, 0);

        // decoded successfully and returned 1 byte.
        assertEquals(Base32String.decode("AA").length, 1);
        assertEquals(Base32String.decode("AAA").length, 1);

        // decoded successfully and returned 2 bytes.
        assertEquals(Base32String.decode("AAAA").length, 2);

        // acceptable separators " " and "-" which should be ignored
        assertEquals(Base32String.decode("AA-AA").length, 2);
        assertEquals(Base32String.decode("AA-AA").length, 2);
        assertTrue(() -> Arrays.equals(Base32String.decode("AA AA"), Base32String.decode("AA-AA")));
        assertTrue(() -> Arrays.equals(Base32String.decode("AA AA"), Base32String.decode("AAAA")));

        // 1, 8, 9, 0 are not a valid character, decoding should fail
        assertThrows(RuntimeException.class, () -> {Base32String.decode("11");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("A1");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA8");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA9");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA0");});

        // non-alphanumerics (except =) are not valid characters and decoding should fail
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA,");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA;");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA.");});
        assertThrows(RuntimeException.class, () -> {Base32String.decode("AAA!");});
    }
}
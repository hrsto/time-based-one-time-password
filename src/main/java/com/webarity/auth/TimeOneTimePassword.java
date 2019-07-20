package com.webarity.auth;

import com.webarity.auth.support.*;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>Defaults:</p>
 * <ul>
 *  <li>TIME_STEP = 30</li>
 *  <li>START_TIME = 0</li>
 *  <li>PIN_LENGTH = 6</li>
 * </ul>
 * @see <a href="https://github.com/google/google-authenticator-android" target="_blank">Google Authenticator</a>
 */
public enum TimeOneTimePassword {

    HMACSHA1("HMACSHA1")

    ;

    private static final int PIN_LENGTH = 6; // TOTP
    private static long TIME_STEP = 30;
    private static long START_TIME = 0;
    private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
            1000000000 };

    private Mac mac;

    private TimeOneTimePassword(String algorithm) {
        try {
            this.mac = Mac.getInstance(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            throw new IllegalArgumentException(ex);
        }
    }

    /**
     * <p>Uses the defaults for ping length, start time, time step. Uses {@code System.currentTimeMillis() / 1000} to get he right-now-time</p>
     *  
     * @param secret shared secret between Google Authenticator and Server
     * @return a 6 digit pin, computed for current step of 30 seconds and start time 0
     * @throws Exception
     */
    public String oneTimePassword(String secret) throws Exception {
        byte[] challenge = ByteBuffer.allocate(8).putLong(getValueAtTime(System.currentTimeMillis() / 1000, START_TIME, TIME_STEP)).array();
        return computePin(secret, challenge, PIN_LENGTH);
    }

    /**
     * 
     * @param secret shared secret between Google Authenticator and Server
     * @param pinLength length of the pin/password
     * @return the pin with the specified length, computed for current step of 30 seconds and start time 0
     * @throws Exception
     */
    public String oneTimePassword(String secret, int pinLength) throws Exception {
        byte[] challenge = ByteBuffer.allocate(8).putLong(getValueAtTime(System.currentTimeMillis() / 1000, START_TIME, TIME_STEP)).array();
        return computePin(secret, challenge, pinLength);
    }

    /**
     * 
     * @param secret shared secret between Google Authenticator and Server
     * @param startTime unix time to start counting time steps, usually it will be 0, see README.md
     * @param timeStep window between new code generation, in seconds
     * @param pinLength length of the pin/password
     * @return the pin with the specified length, computed for current step of 30 seconds and start time 0
     * @throws Exception
     */
    public String oneTimePassword(String secret, long startTime, long timeStep, int pinLength) throws Exception {
        byte[] challenge = ByteBuffer.allocate(8).putLong(getValueAtTime(System.currentTimeMillis() / 1000, startTime, timeStep)).array();
        return computePin(secret, challenge, pinLength);
    }

    /**
     * <p>Control over all attributes. May use the {@code nowTime} for calculating older values in order to account for network delays or slow entry on demand, without actually storing those values to begin with.</p>
     * 
     * @param secret shared secret between Google Authenticator and Server
     * @param nowTime the right now time in Unix; expects seconds, should be in seconds - for ex., {@code System.currentTimeMillis() / 1000}
     * @param startTime unix time to start counting time steps, usually it will be 0, see README.md
     * @param timeStep window between new code generation, in seconds
     * @param pinLength length of the pin/password
     * @return the pin with the specified length, computed for current step of 30 seconds and start time 0
     * @throws Exception
     */
    public String oneTimePassword(String secret, long nowTime, long startTime, long timeStep, int pinLength) throws Exception {
        byte[] challenge = ByteBuffer.allocate(8).putLong(getValueAtTime(nowTime, startTime, timeStep)).array();
        return computePin(secret, challenge, pinLength);
    }

    private int hashToInt(byte[] bytes, int start) {
        DataInput input = new DataInputStream(new ByteArrayInputStream(bytes, start, bytes.length - start));
        int val;
        try {
            val = input.readInt();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return val;
    }

    private String computePin(String secret, byte[] challenge, int pingLength) throws Exception {
        if (pingLength > DIGITS_POWER.length) throw new IllegalArgumentException("Pin length can't exceed 9.");

        byte[] keyBytes = Base32String.decode(secret);
        mac.init(new SecretKeySpec(keyBytes, ""));

        byte[] hash = mac.doFinal(challenge);

        int offset = hash[hash.length - 1] & 0xF;
        // Grab a positive integer value starting at the given offset.
        int truncatedHash = hashToInt(hash, offset) & 0x7FFFFFFF;
        int pinValue = truncatedHash % DIGITS_POWER[pingLength];
        return String.format("%0".concat(Integer.toString(pingLength)).concat("d"), pinValue);
    }

    private static long getValueAtTime(long time, long startTime, long timeStep) {

        long timeSinceStartTime = time - startTime;
        if (timeSinceStartTime >= 0) {
            return timeSinceStartTime / timeStep;
        } else {
            return (timeSinceStartTime - (timeStep - 1)) / timeStep;
        }
    }
    
}
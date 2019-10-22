# Java Implementation of TOTP: Time-Based One-Time Password Algorithm

Uses [Google Authenticator](https://github.com/google/google-authenticator-android) as the base to provide quick and dirty library as a start for further development of 2fa solutions based on TOTP.

## Usage

Get the dependency via Maven with coords:

```xml
<dependency>
  <groupId>com.webarity</groupId>
  <artifactId>time-based-one-time-password</artifactId>
  <version>1.0.0</version>
</dependency>
```

Install Google Authenticator (or anything similar to it from anywhere) from the google play store and set it up for time based passwords and give it a shared secret. Then:

```java
TimeOneTimePassword.HMACSHA1.oneTimePassword("mysharedsecrethere"); //uses the defaults of 0 unix start time, 30 seconds interval steps, and 6 pin length
TimeOneTimePassword.HMACSHA1.oneTimePassword("mysharedsecrethere", 6); //with pin length
TimeOneTimePassword.HMACSHA1.oneTimePassword("mysharedsecrethere", 0, 30, 6); //with start time, time step, and pin lenght
TimeOneTimePassword.HMACSHA1.oneTimePassword("mysharedsecrethere", System.currentTimeMillis() / 1000, 0, 30, 6); //with the current _now_ time in seconds, start time, time step, and pin length
```

## Abstract

For reference, see [RFC 6238 TOTP: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238).

Abbreviations used:

* HOTP - HMAC one time password (with SHA1 hash function)
* TOTP - time base one time password
* OTP - one time password

Algorithm is defined as:

```text
T = Math.floor((Ut - T0) / X)
TOTP = HOTP(K,T)
```

Where:

* Ut - current Unix epoch time in seconds. In java it would look like `System.currentTimeMillis() / 1000`. In JavaScript - `Date.now() / 1000`
* X - time step in seconds (30 by default for Google Authenticator)
* T0 - unix time to start counting time steps, defaults to 0

HOTP uses HMAC SHA 1 and is applied to increasing counter value that represents the message in the HMAC computation. The result is then truncated to obtain user-friendly vals using:

```text
HOTP(K, C) = Truncate(HMAK-sha-1(K, C))
```

Truncate converts HMAC SHA 1 val into HOTP value.

* K - shared secret
* C - counter value - in TOTP, this val will be T (see above). TOTP may use SHA 256 or SHA 512 instead of HMAC SHA 1.

Due to lag, when client sends his OTP, server may receive it when the time window ends, thus the server may have to allow for a buffer time and compare the received OTP with, at most, the previous one.

---

<https://www.webarity.com>

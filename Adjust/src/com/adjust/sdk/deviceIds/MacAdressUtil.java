package com.adjust.sdk.deviceIds;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Locale;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.text.TextUtils;

public class MacAdressUtil {
    private static String MD5      = "MD5";
    private static String SHA1     = "SHA-1";
    private static String ENCODING = "UTF-8";

    public static String getMacSha1(Context context) {
        String macAddress = getMacAddress(context);
        if (macAddress == null) {
            return null;
        }
        String macSha1 = sha1(macAddress);

        return macSha1;
    }

    public static String getMacShortMd5(Context context) {
        String macAddress = getMacAddress(context);
        if (macAddress == null) {
            return null;
        }
        String macShort = macAddress.replaceAll(":", "");
        String macShortMd5 = md5(macShort);

        return macShortMd5;
    }

    private static String getMacAddress(Context context) {
        final String rawAddress = getRawMacAddress(context);
        if (rawAddress == null) {
            return null;
        }
        final String upperAddress = rawAddress.toUpperCase(Locale.US);
        return sanitizeString(upperAddress);
    }

    private static String getRawMacAddress(Context context) {
        // android devices should have a wlan address
        final String wlanAddress = loadAddress("wlan0");
        if (wlanAddress != null) {
            return wlanAddress;
        }

        // emulators should have an ethernet address
        final String ethAddress = loadAddress("eth0");
        if (ethAddress != null) {
            return ethAddress;
        }

        // query the wifi manager (requires the ACCESS_WIFI_STATE permission)
        try {
            final WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            final String wifiAddress = wifiManager.getConnectionInfo().getMacAddress();
            if (wifiAddress != null) {
                return wifiAddress;
            }
        } catch (Exception e) {
            /* no-op */
        }

        return null;
    }

    private static String loadAddress(final String interfaceName) {
        try {
            final String filePath = "/sys/class/net/" + interfaceName + "/address";
            final StringBuilder fileData = new StringBuilder(1000);
            final BufferedReader reader = new BufferedReader(new FileReader(filePath), 1024);
            final char[] buf = new char[1024];
            int numRead;

            String readData;
            while ((numRead = reader.read(buf)) != -1) {
                readData = String.valueOf(buf, 0, numRead);
                fileData.append(readData);
            }

            reader.close();
            return fileData.toString();
        } catch (IOException e) {
            return null;
        }
    }

    private static String sanitizeString(final String inputString) {
        if (TextUtils.isEmpty(inputString)) {
            return null;
        }

        String outputString = inputString.replaceAll("\\s", "");
        if (TextUtils.isEmpty(outputString)) {
            return null;
        }

        return outputString;
    }

    private static String sha1(final String text) {
        return hash(text, SHA1);
    }

    private static String md5(final String text) {
        return hash(text, MD5);
    }

    private static String hash(final String text, final String method) {
        try {
            final byte[] bytes = text.getBytes(ENCODING);
            final MessageDigest mesd = MessageDigest.getInstance(method);
            mesd.update(bytes, 0, bytes.length);
            final byte[] hash = mesd.digest();
            return convertToHex(hash);
        } catch (Exception e) {
            return null;
        }
    }

    private static String convertToHex(final byte[] bytes) {
        final BigInteger bigInt = new BigInteger(1, bytes);
        final String formatString = "%0" + (bytes.length << 1) + "x";
        return String.format(formatString, bigInt);
    }
}

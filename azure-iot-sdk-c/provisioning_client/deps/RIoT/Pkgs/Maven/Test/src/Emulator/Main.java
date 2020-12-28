package Emulator;

import com.microsoft.msr.RiotEmulator.RIoT;

import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class Main {


    public static void main(String[] args) {
        try {
            RIoT.DeviceAuthBundle devAuth0 = RIoT.CreateDeviceAuthBundle(
                    hstoba("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
                    hstoba("AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB"),
                    false);

            RIoT.DeviceAuthBundle devAuth1 = RIoT.CreateDeviceAuthBundle(
                    hstoba("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
                    hstoba("AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB"),
                    false);

            // NEED TO MATCH WITH SAME SEEDS



            if (devAuth0.AliasPrivateKeyPem.equals(devAuth1.AliasPrivateKeyPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            if (devAuth0.AliasCertPem.equals(devAuth1.AliasCertPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            //System.out.println(devAuth0.DeviceIDCertPem);
            //System.out.println(devAuth1.DeviceIDCertPem);

            if (devAuth0.DeviceIDCertPem.equals(devAuth1.DeviceIDCertPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            //System.out.println(devAuth0.AliasCertPem);
            //System.out.println(devAuth1.AliasCertPem);

            if (devAuth0.AliasCertPem.equals(devAuth1.AliasCertPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            RIoT.DeviceAuthBundle devAuth2 = RIoT.CreateDeviceAuthBundle(
                    hstoba("1123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
                    hstoba("BABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB"),
                    false);

            // NEED TO !MATCH WITH !SAME SEEDS

            if (devAuth2.AliasPrivateKeyPem.equals(devAuth1.AliasPrivateKeyPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            if (devAuth2.AliasCertPem.equals(devAuth1.AliasCertPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            //System.out.println(devAuth0.DeviceIDCertPem);
            //System.out.println(devAuth1.DeviceIDCertPem);

            if (devAuth2.DeviceIDCertPem.equals(devAuth1.DeviceIDCertPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            //System.out.println(devAuth0.AliasCertPem);
            //System.out.println(devAuth1.AliasCertPem);

            if (devAuth2.AliasCertPem.equals(devAuth1.AliasCertPem)) {
                System.out.println("Match!");
            } else {
                System.out.println("No Match!");
            }

            RIoT.DeviceAuthBundle devAuth3 = RIoT.CreateDeviceAuthBundle(
                    hstoba("1123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
                    hstoba("BABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB"),
                    false, "RIoT r00t", "RIoT Core", "RIoT Device");

            System.out.println(devAuth3.RootCertPem);
            System.out.println(devAuth3.DeviceIDCertPem);
            System.out.println(devAuth3.AliasCertPem);

            System.out.println(devAuth0.DeviceIDPublicPem);

            if(devAuth0.RootPrivateKeyPem.equals(devAuth2.RootPrivateKeyPem)) {
                System.out.println("R00t CA Keys are good");
            } else {
                System.out.println("R00t CA Keys are no good");
            }

            // Check validity and verify signatures
            devAuth0.RootCert.checkValidity();
            devAuth0.RootCert.verify(devAuth0.RootPublicKey);

            devAuth0.DeviceIDCert.checkValidity();
            devAuth0.DeviceIDCert.verify(devAuth0.RootPublicKey);

            devAuth0.AliasCert.checkValidity();
            devAuth0.AliasCert.verify(devAuth0.DeviceIDPublic);

            RIoT.CreateLeafCert(devAuth0, "testing");
            devAuth0.LeafCert.verify(devAuth0.RootPublicKey);
            System.out.println(devAuth0.LeafCertPem);

/*            *//* TLS HANDSHAKE *//*
            String password = "";
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca-cert", devAuth3.RootCert);
            keyStore.setCertificateEntry("client-cert", devAuth3.AliasCert);
            keyStore.setKeyEntry("client-key", devAuth3.AliasPrivateKey, password.toCharArray(),
                    new Certificate[] {devAuth3.AliasCert, devAuth3.DeviceIDCert, devAuth3.RootCert});

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password.toCharArray());

            KeyManager[] keyManagers = kmf.getKeyManagers();

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            TrustManager[] tm = new TrustManager[] {(TrustManager) new NulledTrustManager()};

            sslContext.init(keyManagers, tm, new SecureRandom());

            SSLSocketFactory sslSF = (SSLSocketFactory)
                    sslContext.getSocketFactory();
            System.out.println(" Creating and opening new SSLSocket withSSLSocketFactory");

            SSLSocket sslSock = (SSLSocket) sslSF.createSocket("localhost", 5556);

            sslSock.startHandshake();

            sslSock.getOutputStream().write(new byte[] {1,2,3,4});
            System.out.println("Stream works");

            System.out.println("Success");
*/
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static class NulledTrustManager implements X509TrustManager{
        public boolean certificateCallback(X509Certificate[] o, int validateErr) {
            System.out.println(" --- Do Not Use In Production ---\n");
            for (int i=0; i<o.length; i++)
                System.out.println(" certificate " + i + " -- " + o[i].toString());
            return true;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] o, String arg1) {
            // TODO Auto-generated method stub
            for (int i=0; i<o.length; i++)
                System.out.println(" certificate " + i + " -- " + o[i].toString());
        }

        @Override
        public void checkServerTrusted(X509Certificate[] o, String arg1)  {
            // TODO Auto-generated method stub
            for (int i=0; i<o.length; i++)
                System.out.println(" certificate " + i + " -- " + o[i].toString());
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            // TODO Auto-generated method stub
            return null;
        }
    }

    /**
     * Convert a hex string to an array of bytes
     * @param s Hex string to convert
     * @return Converted byte array
     */
    private static byte[] hstoba(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}

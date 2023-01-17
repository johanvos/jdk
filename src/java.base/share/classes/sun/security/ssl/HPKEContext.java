package sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static sun.security.ssl.NamedGroup.X25519;
import static sun.security.ssl.SomeWork.extractAndExpand;

public class HPKEContext {

    private final KeyPair ephemeralKeyPair;
    private final PublicKey remotePublicKey;
    private final byte[] info;

    private byte[] nonce;
    private byte[] key;

    /**
     *
     * @param pkR the PublicKey of the Remote peer
     */
    HPKEContext(PublicKey pkR, byte[] info) throws IOException {
        this(pkR, deriveKeyPair(null), info);
    }

    HPKEContext(PublicKey pkR, KeyPair ephemeral, byte[] info) {
        this.remotePublicKey = pkR;
        this.ephemeralKeyPair = ephemeral;
        this.info = info;
    }

    HPKEContext(byte[] nonce, byte[] key, byte[] info) {
        this.nonce = nonce;
        this.key = key;
        this.info = info;
        this.ephemeralKeyPair = null;
        this.remotePublicKey = null;
    }

    void create() throws IOException {
        byte[] sharedSecret = encapsulate(ephemeralKeyPair, remotePublicKey);
        SSLLogger.info("SHAREDSECRET", sharedSecret);
        do_middle(sharedSecret);
    }

    void do_middle(byte[] sharedSecret) throws IOException {
        System.err.println("DO_MIDDLE start");
        byte[] l1 = labeledExtract("".getBytes(), "psk_id_hash".getBytes(), SUITEID2, "".getBytes());
        System.err.println("Extract phase 1: " + Arrays.toString(l1));
        byte[] l2 = labeledExtract("".getBytes(), "info_hash".getBytes(), SUITEID2, info);
        System.err.println("Extract phase 2: " + Arrays.toString(l2));
        byte[] key_schedule_context = new byte[l1.length + l2.length + 1];
        key_schedule_context[0] = 0;
        System.arraycopy(l1, 0, key_schedule_context, 1, l1.length);
        System.arraycopy(l2, 0, key_schedule_context, l1.length + 1, l2.length);

        byte[] secret = labeledExtract(sharedSecret, "secret".getBytes(), SUITEID2, "".getBytes());
        System.err.println("secret bytes = " + Arrays.toString(secret));
        byte[] mykey = labeledExpand(secret, "key".getBytes(), key_schedule_context, SUITEID2, 16);
        System.err.println("key = " + Arrays.toString(mykey));
        byte[] base_nonce = labeledExpand(secret, "base_nonce".getBytes(), key_schedule_context, SUITEID2, 12);
        System.err.println("base_nonce = " + Arrays.toString(base_nonce));
        byte[] exporter_secret = labeledExpand(secret, "exp".getBytes(), key_schedule_context, SUITEID2, 32);
        System.err.println("exporter_secret = " + Arrays.toString(exporter_secret));
        System.err.println("DO_MIDDLE done");
        this.key = mykey;
        this.nonce = base_nonce;
    }

    // dhkem_extract_and_expand
    private byte[] encapsulate(KeyPair ephemeralPair, PublicKey remotePk) throws IOException {
        try {
            PrivateKey sk = ephemeralPair.getPrivate();
            PublicKey pkEm = ephemeralPair.getPublic();
            NamedGroup ng = NamedGroup.X25519;
            KeyAgreement ka = KeyAgreement.getInstance(ng.algorithm);
            ka.init(sk);
            Key sharedKey = ka.doPhase(remotePk, true);
            byte[] dh = ka.generateSecret();
            byte[] kemContext = new byte[64];
            System.arraycopy(pkEm.getEncoded(), 12, kemContext, 0, 32);
            System.arraycopy(remotePk.getEncoded(), 12, kemContext, 32, 32);
            byte[] sharedSecret = extractAndExpand(dh, kemContext);
            return sharedSecret;
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new IOException(ex);
        }
    }

    byte[] seal(byte[] aad, byte[] pt) throws IOException {
        try {
            // we assume aeadId = 0x0001 which is AES-GCM-128
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = this.nonce;
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
            
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            cipher.updateAAD(aad);
            System.err.println("Got cipher: " + cipher);
            byte[] fin = cipher.doFinal(pt);
            SSLLogger.info("Cipher", fin);
            return fin;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new IOException (ex);
        }
    }

    /**
     * Convert the encoded bytes from an X25519 public key into a public key.
     * See HKDF for a similar operation
     *
     * @param uBytes
     * @return a public key
     * @throws IOException whenever something goes wrong.
     */
    static PublicKey convertEncodedPublicKey(byte[] uBytes) throws IOException {
        try {
            NamedGroup ng = NamedGroup.X25519;
            Utilities.reverseBytes(uBytes);
            BigInteger u = new BigInteger(1, uBytes);
            XECPublicKeySpec xecPublicKeySpec = new XECPublicKeySpec(
                    new NamedParameterSpec(ng.name), u);
            KeyFactory factory = KeyFactory.getInstance(ng.algorithm);
            XECPublicKey publicKey = (XECPublicKey) factory.generatePublic(
                    xecPublicKeySpec);
            return publicKey;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public static KeyPair deriveKeyPair(byte[] ikm) throws IOException {
        try {
            if (ikm == null) {
                ikm = new byte[32];
                new Random().nextBytes(ikm);
            }
            HKDF hkdf = new HKDF("SHA256");
            SecretKeySpec salt = null;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.writeBytes("HPKE-v1".getBytes());
            baos.writeBytes(SUITEID);
            baos.writeBytes("dkp_prk".getBytes());
            baos.writeBytes(ikm);
            byte[] fullikm = baos.toByteArray();
            SecretKeySpec inputKey = new SecretKeySpec(fullikm, "HKDF-IMK");
            SecretKey extract = hkdf.extract(salt, inputKey, "dpk_prk");
            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            baos2.writeBytes(new byte[]{0x0, 0x20});
            baos2.writeBytes("HPKE-v1".getBytes());
            baos2.writeBytes(SUITEID);
            baos2.writeBytes("sk".getBytes());
            byte[] ikm2 = baos2.toByteArray();
            SecretKey expand = hkdf.expand(extract, ikm2, 32, "HKDF");
            byte[] eencoded = expand.getEncoded();

            NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
            KeyFactory kf = KeyFactory.getInstance("XDH");
            KeySpec privateSpec = new XECPrivateKeySpec(paramSpec, eencoded);

            PrivateKey myPrivateKey = kf.generatePrivate(privateSpec);
            PublicKey myPublicKey = generatePublicKeyFromPrivate((XECPrivateKey) myPrivateKey);
            KeyPair keypair = new KeyPair(myPublicKey, myPrivateKey);
            return keypair;
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }

    static byte[] labeledExtract(byte[] salt, byte[] label, byte[] suite_id, byte[] ikm) {
        try {
            byte[] labeled_ikm = concat("HPKE-v1".getBytes(), concat(suite_id, concat(label, ikm)));
            HKDF hkdf = new HKDF("SHA256");
            SecretKeySpec inputKey = new SecretKeySpec(labeled_ikm, "HKDF-IMK");
            SecretKeySpec saltks = null;
            if (salt.length > 0) {
                saltks = new SecretKeySpec(salt, "HmacSHA256");
            }
            return hkdf.extract(saltks, inputKey, "hkdf").getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    static byte[] labeledExpand(byte[] prk, byte[] label, byte[] info, byte[] suite_id, int l) throws IOException {
        try {
            byte hi = (byte) (l / 256);
            byte lo = (byte) (l % 256);
            byte[] labeled_info = concat(new byte[]{hi, lo}, concat("HPKE-v1".getBytes(), concat(suite_id, concat(label, info))));
            System.err.println("Labeledexpand, linfosize = " + labeled_info.length + " content = " + Arrays.toString(labeled_info));
            HKDF hkdf = new HKDF("SHA256");
            return hkdf.expand(new SecretKeySpec(prk, "HmacSHA256"), labeled_info, l, "HPKE").getEncoded();

        //    return expand(prk, labeled_info, l);
        } catch (Exception ex) {
            throw new IOException(ex);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        int al = a.length;
        int bl = b.length;
        byte[] c = new byte[al + bl];
        System.arraycopy(a, 0, c, 0, al);
        System.arraycopy(b, 0, c, al, bl);
        return c;
    }

    private static PublicKey generatePublicKeyFromPrivate(XECPrivateKey privateKey) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(X25519.name);
        keyPairGenerator.initialize(new NamedParameterSpec(X25519.name), new StaticSecureRandom(privateKey.getScalar().get()));
        return keyPairGenerator.generateKeyPair().getPublic();
    }

    public static class StaticSecureRandom extends SecureRandom {

        private static final long serialVersionUID = 1234567L;

        private final byte[] privateKey;

        public StaticSecureRandom(byte[] privateKey) {
            this.privateKey = privateKey.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(privateKey, 0, bytes, 0, privateKey.length);
        }

    }

    private static final byte[] SUITEID = new byte[]{0x4b, 0x45, 0x4d, 0x0, 0x20}; //KEM0x0020
    private static final byte[] SUITEID2 = new byte[]{0x48, 0x50, 0x4B, 0x45, 0x0, 0x20, 0x0, 0x1, 0x0, 0x1}; //HPKE[kemid,kdfid,aeadid]

}

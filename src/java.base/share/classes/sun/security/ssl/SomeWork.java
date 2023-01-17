/*
 * Copyright (c) 2015, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static sun.security.ssl.ClientHello.generatePublicKeyFromPrivate;
import static sun.security.ssl.ClientHello.getIterationStartOffset;

class SomeWork {
    
    static final byte[] SUITEID = new byte[]{0x4b, 0x45, 0x4d, 0x0, 0x20}; //KEM0x0020
    static final byte[] SUITEID2 = new byte[]{0x48,0x50,0x4B,0x45,0x0,0x20,0x0,0x1,0x0,0x1}; //HPKE[kemid,kdfid,aeadid]

    static byte[] ikmR = HexFormat.of().parseHex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    static byte[] ikme = HexFormat.of().parseHex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    static byte[] aad = HexFormat.of().parseHex("436f756e742d30");
    static byte[] pt = HexFormat.of().parseHex("4265617574792069732074727574682c20747275746820626561757479");

    static void test9180A11() {
        try {
            KeyPair ephemeralKeyPair = deriveKeyPair(ikme);
            System.err.println("pkEm = " + Arrays.toString(ephemeralKeyPair.getPublic().getEncoded()));
            System.err.println("skEm = " + Arrays.toString(ephemeralKeyPair.getPrivate().getEncoded()));
            KeyPair receiverKeyPair = deriveKeyPair(ikmR);
            System.err.println("pkRm = " + Arrays.toString(receiverKeyPair.getPublic().getEncoded()));
            System.err.println("skRm = " + Arrays.toString(receiverKeyPair.getPrivate().getEncoded()));
            XECPrivateKey xpk = (XECPrivateKey)ephemeralKeyPair.getPrivate();
            System.err.println("format = " +xpk.getFormat());
            System.err.println("enc = "+Arrays.toString(xpk.getEncoded()));
            System.err.println("scalar = "+Arrays.toString(xpk.getScalar().get()));
            HpkeContext context = OSSL_HPKE_encap(ephemeralKeyPair, receiverKeyPair.getPublic());
            OSSL_HPKE_seal(context, aad, pt);
        } catch (Exception ex) {
            System.err.println("PROBLEM!!!!\n\n\n");
            ex.printStackTrace();
        }
    }

    static HpkeContext OSSL_HPKE_encap(KeyPair ephemeralKeyPair, PublicKey remotePub) throws Exception {
        byte[] sharedSecret = encapsulate(ephemeralKeyPair, remotePub);
        return do_middle(sharedSecret);
    }

    static void OSSL_HPKE_seal(HpkeContext context, byte[] aad, byte[] pt) throws Exception {
        // we assume aeadId = 0x0001 which is AES-GCM-128
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = context.nonce;
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
        
        SecretKey secretKey = new SecretKeySpec(context.key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        cipher.updateAAD(aad);
        System.err.println("Got cipher: " + cipher);
        byte[] fin = cipher.doFinal(pt);
        byte[] answer = new byte[pt.length + 16];
        SSLLogger.info("Cipher", fin);
    }
    
   static HpkeContext do_middle(byte[] sharedSecret) {
       System.err.println("DO_MIDDLE start");
        byte[] l1 = labeledExtract("".getBytes(),"psk_id_hash".getBytes(), SUITEID2, "".getBytes());
        System.err.println("Extract phase 1: "+Arrays.toString(l1));
        byte[] info = "Ode on a Grecian Urn".getBytes();
        byte[] l2 = labeledExtract("".getBytes(),"info_hash".getBytes(), SUITEID2, info);
        System.err.println("Extract phase 2: "+Arrays.toString(l2));
        byte[] key_schedule_context = new byte[l1.length+l2.length+1];
        key_schedule_context[0] = 0;
        System.arraycopy(l1, 0, key_schedule_context, 1, l1.length);
        System.arraycopy(l2, 0, key_schedule_context, l1.length+1, l2.length);
        
        byte[] secret = labeledExtract(sharedSecret, "secret".getBytes(), SUITEID2,"".getBytes());
        System.err.println("secret bytes = "+Arrays.toString(secret));
        byte[] key = labeledExpand(secret, "key".getBytes(), key_schedule_context, SUITEID2,16);
        System.err.println("key = "+Arrays.toString(key));
        byte[] base_nonce = labeledExpand(secret, "base_nonce".getBytes(), key_schedule_context, SUITEID2, 12);
        System.err.println("base_nonce = " + Arrays.toString(base_nonce));
        byte[] exporter_secret = labeledExpand(secret, "exp".getBytes(), key_schedule_context, SUITEID2, 32);
        System.err.println("exporter_secret = " + Arrays.toString(exporter_secret));
        System.err.println("DO_MIDDLE done");
        HpkeContext answer = new HpkeContext();
        answer.key = key;
        answer.nonce = base_nonce;
        return answer;
   }
    static KeyPair deriveKeyPair(byte[] ikm) {
        try {
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

            byte[] encoded = extract.getEncoded();
            SSLLogger.info("intermediate key", encoded);

            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            baos2.writeBytes(new byte[]{0x0, 0x20});
            baos2.writeBytes("HPKE-v1".getBytes());
            baos2.writeBytes(SUITEID);
            baos2.writeBytes("sk".getBytes());
            byte[] ikm2 = baos2.toByteArray();
            SecretKey expand = hkdf.expand(extract, ikm2, 32, "HKDF");
            SSLLogger.info("ikm2 = ", ikm2);
            byte[] eencoded = expand.getEncoded();
            SSLLogger.info("new key", eencoded);

            NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
            KeyFactory kf = KeyFactory.getInstance("XDH");
            KeySpec privateSpec = new XECPrivateKeySpec(paramSpec, eencoded);
            
            PrivateKey myPrivateKey = kf.generatePrivate(privateSpec);
            System.err.println("IN M, scalar = " +Arrays.toString(((XECPrivateKey)myPrivateKey).getScalar().get()));
            PublicKey myPublicKey = generatePublicKeyFromPrivate((XECPrivateKey) myPrivateKey);
            KeyPair keypair = new KeyPair(myPublicKey, myPrivateKey);
            return keypair;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    // dhkem_extract_and_expand
    static private byte[] encapsulate(KeyPair ephemeralPair, PublicKey remotePk) throws Exception {
        PrivateKey sk = ephemeralPair.getPrivate();
        PublicKey pkEm = ephemeralPair.getPublic();
        NamedGroup ng = NamedGroup.X25519;
        KeyAgreement ka = KeyAgreement.getInstance(ng.algorithm);
        System.err.println("2");
        ka.init(sk);
        System.err.println("3");
        Key sharedKey = ka.doPhase(remotePk, true);
        System.err.println("4bis");
        byte[] dh = ka.generateSecret();
        System.err.println("sharedkey = " + sharedKey);
        System.err.println("dhsharedkey = " + Arrays.toString(dh));
        System.err.println("remote PUBKEY = " + Arrays.toString(remotePk.getEncoded())+ " and len = "+remotePk.getEncoded().length);
        System.err.println("PUBKEY = " + Arrays.toString(pkEm.getEncoded())+ " and len = "+pkEm.getEncoded().length);
    byte[] kemContext = new byte[64];
    System.arraycopy(pkEm.getEncoded(), 12, kemContext, 0, 32);
    System.arraycopy(remotePk.getEncoded(), 12, kemContext, 32, 32);
        System.err.println("kemctx = "+Arrays.toString(kemContext)); 
    byte[] sharedSecret = extractAndExpand(dh, kemContext);
        System.err.println("SharedSecret = "+Arrays.toString(sharedSecret));
        return sharedSecret;
    }
    
//    dhkem_extract_and_expand
    static byte[] extractAndExpand(byte[] dh, byte[] kemctx) {
        int Nsecret = 32;
        byte[] eae_prk = labeledExtract("".getBytes(), "eae_prk".getBytes(), SUITEID, dh);
        System.err.println("Result of firstextract " + Arrays.toString(eae_prk));
        byte[] shared_secret = labeledExpand(eae_prk, "shared_secret".getBytes(),
                kemctx,SUITEID, Nsecret);
        return shared_secret;
    }

    static byte[] labeledExtract(byte[] salt, byte[] label, byte[] suite_id, byte[] ikm) {
        byte[] labeled_ikm = concat("HPKE-v1".getBytes(), concat(suite_id, concat(label, ikm)));
        System.err.println("LabeledExtract, likm("+ labeled_ikm.length+") = "+Arrays.toString(labeled_ikm));
        return extract(salt, labeled_ikm);
    }

    static byte[] labeledExpand(byte[] prk, byte[] label, byte[] info, byte[] suite_id, int l) {
        byte hi = (byte) (l/256);
        byte lo = (byte) (l%256);
        byte[] labeled_info = concat(new byte[]{hi, lo}, concat("HPKE-v1".getBytes(), concat(suite_id, concat(label, info))));
        System.err.println("Labeledexpand, linfosize = "+labeled_info.length+" content = "+Arrays.toString(labeled_info));
        return expand(prk, labeled_info, l);
    }

    static private byte[] extract(byte[] salt, byte[] inputKeyMaterial) {
        System.err.println("extract with "+inputKeyMaterial.length+" bytes.");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            if ((salt == null) || (salt.length == 0)) {
                salt = new byte[inputKeyMaterial.length];
                for (int i = 0; i < salt.length;i++) salt[i] = (byte)0;
            }
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(inputKeyMaterial);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    static final int HASH_OUTPUT_SIZE=32;

    static private byte[] expand(byte[] prk, byte[] info, int outputSize) {
        try {
            int iterations = (int) Math.ceil((double) outputSize / (double) HASH_OUTPUT_SIZE);
            byte[] mixin = new byte[0];
            ByteArrayOutputStream results = new ByteArrayOutputStream();
            int remainingBytes = outputSize;

            for (int i = getIterationStartOffset(); i < iterations + getIterationStartOffset(); i++) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));

                mac.update(mixin);
                if (info != null) {
                    mac.update(info);
                }
                mac.update((byte) i);

                byte[] stepResult = mac.doFinal();
                int stepSize = Math.min(remainingBytes, stepResult.length);

                results.write(stepResult, 0, stepSize);

                mixin = stepResult;
                remainingBytes -= stepSize;
            }

            return results.toByteArray();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
    static byte[] concat(byte[] a, byte[] b) {
        int al = a.length; 
        int bl = b.length;
        byte[] c = new byte[al + bl];
        System.arraycopy(a, 0, c, 0, al);
        System.arraycopy(b, 0, c, al, bl);
        System.err.println("contact "+Arrays.toString(a)+" and "+Arrays.toString(b)+" and return " + Arrays.toString(c));
        return c;        
    }
    
    static class HpkeContext {
        byte[] key;
        byte[] nonce;
    }
}

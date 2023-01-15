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
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import static sun.security.ssl.ClientHello.SUITEID;
import static sun.security.ssl.ClientHello.generatePublicKeyFromPrivate;

class SomeWork {

    static void deriveKeyPair(byte[] ikm) {
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
            PrivateKey privateKey = kf.generatePrivate(privateSpec);

            PublicKey mypubkey = generatePublicKeyFromPrivate((XECPrivateKey) privateKey);

            SSLLogger.info("SOMEderiveKeyPair results in ", mypubkey);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}

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
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
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
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.text.MessageFormat;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import static sun.security.ssl.ClientAuthType.CLIENT_AUTH_REQUIRED;
import static sun.security.ssl.NamedGroup.X25519;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SupportedVersionsExtension.CHSupportedVersionsSpec;

/**
 * Pack of the ClientHello handshake message.
 */
final class ClientHello {
        static final int OSSL_ECH_PADDING_TARGET = 256;
    static final int OSSL_ECH_PADDING_INCREMENT = 32;
    static final String OSSL_ECH_CONTEXT_STRING = "tls ech";
    
    static final SSLProducer kickstartProducer =
        new ClientHelloKickstartProducer();
    static final SSLConsumer handshakeConsumer =
        new ClientHelloConsumer();
    static final HandshakeProducer handshakeProducer =
        new ClientHelloProducer();

    private static final HandshakeConsumer t12HandshakeConsumer =
            new T12ClientHelloConsumer();
    private static final HandshakeConsumer t13HandshakeConsumer =
            new T13ClientHelloConsumer();
    private static final HandshakeConsumer d12HandshakeConsumer =
            new D12ClientHelloConsumer();
    private static final HandshakeConsumer d13HandshakeConsumer =
            new D13ClientHelloConsumer();

    /**
     * The ClientHello handshake message.
     *
     * See RFC 5264/4346/2246/6347 for the specifications.
     */
    static final class ClientHelloMessage extends HandshakeMessage {
        private final boolean       isDTLS;

        final int                   clientVersion;
        final RandomCookie          clientRandom;
        final SessionId             sessionId;
        private byte[]              cookie;         // DTLS only
        final int[]                 cipherSuiteIds;
        final List<CipherSuite>     cipherSuites;   // known cipher suites only
        final byte[]                compressionMethod;
        final SSLExtensions         extensions;

        private static final byte[]  NULL_COMPRESSION = new byte[] {0};

        ClientHelloMessage(HandshakeContext handshakeContext,
                int clientVersion, SessionId sessionId,
                List<CipherSuite> cipherSuites, SecureRandom generator) {
            super(handshakeContext);
            this.isDTLS = handshakeContext.sslContext.isDTLS();

            this.clientVersion = clientVersion;
            this.clientRandom = new RandomCookie(generator);
            this.sessionId = sessionId;
            if (isDTLS) {
                this.cookie = new byte[0];
            } else {
                this.cookie = null;
            }

            this.cipherSuites = cipherSuites;
            this.cipherSuiteIds = getCipherSuiteIds(cipherSuites);
            this.extensions = new SSLExtensions(this);

            // Don't support compression.
            this.compressionMethod = NULL_COMPRESSION;
        }

        /* Read up to the binders in the PSK extension. After this method
         * returns, the ByteBuffer position will be at end of the message
         * fragment that should be hashed to produce the PSK binder values.
         * The client of this method can use this position to determine the
         * message fragment and produce the binder values.
         */
        static void readPartial(TransportContext tc,
                ByteBuffer m) throws IOException {
            boolean isDTLS = tc.sslContext.isDTLS();

            // version
            Record.getInt16(m);

            new RandomCookie(m);

            // session ID
            Record.getBytes8(m);

            // DTLS cookie
            if (isDTLS) {
                Record.getBytes8(m);
            }

            // cipher suite IDs
            Record.getBytes16(m);
            // compression method
            Record.getBytes8(m);
            // read extensions, if present
            if (m.remaining() >= 2) {
                int remaining = Record.getInt16(m);
                while (remaining > 0) {
                    int id = Record.getInt16(m);
                    int extLen = Record.getInt16(m);
                    remaining -= extLen + 4;

                    if (id == SSLExtension.CH_PRE_SHARED_KEY.id) {
                        // ensure pre_shared_key is the last extension
                        if (remaining > 0) {
                            throw tc.fatal(Alert.ILLEGAL_PARAMETER,
                                    "pre_shared_key extension is not last");
                        }
                        // read only up to the IDs
                        Record.getBytes16(m);
                        return;
                    } else {
                        m.position(m.position() + extLen);

                    }
                }
            }   // Otherwise, ignore the remaining bytes.
        }

        ClientHelloMessage(HandshakeContext handshakeContext, ByteBuffer m,
                SSLExtension[] supportedExtensions) throws IOException {
            super(handshakeContext);
            this.isDTLS = handshakeContext.sslContext.isDTLS();

            this.clientVersion = ((m.get() & 0xFF) << 8) | (m.get() & 0xFF);
            this.clientRandom = new RandomCookie(m);
            this.sessionId = new SessionId(Record.getBytes8(m));
            try {
                sessionId.checkLength(clientVersion);
            } catch (SSLProtocolException ex) {
                throw handshakeContext.conContext.fatal(
                        Alert.ILLEGAL_PARAMETER, ex);
            }
            if (isDTLS) {
                this.cookie = Record.getBytes8(m);
            } else {
                this.cookie = null;
            }

            byte[] encodedIds = Record.getBytes16(m);
            if (encodedIds.length == 0 || (encodedIds.length & 0x01) != 0) {
                throw handshakeContext.conContext.fatal(
                        Alert.ILLEGAL_PARAMETER,
                        "Invalid ClientHello message");
            }

            this.cipherSuiteIds = new int[encodedIds.length >> 1];
            for (int i = 0, j = 0; i < encodedIds.length; i++, j++) {
                cipherSuiteIds[j] =
                    ((encodedIds[i++] & 0xFF) << 8) | (encodedIds[i] & 0xFF);
            }
            this.cipherSuites = getCipherSuites(cipherSuiteIds);

            this.compressionMethod = Record.getBytes8(m);
            // In TLS 1.3, use of certain extensions is mandatory.
            if (m.hasRemaining()) {
                this.extensions =
                        new SSLExtensions(this, m, supportedExtensions);
            } else {
                this.extensions = new SSLExtensions(this);
            }
        }

        void setHelloCookie(byte[] cookie) {
            this.cookie = cookie;
        }

        // DTLS 1.0/1.2, for cookie generation.
        byte[] getHelloCookieBytes() {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                // copied from send() method
                hos.putInt8((byte)((clientVersion >>> 8) & 0xFF));
                hos.putInt8((byte)(clientVersion & 0xFF));
                hos.write(clientRandom.randomBytes, 0, 32);
                hos.putBytes8(sessionId.getId());
                // ignore cookie
                hos.putBytes16(getEncodedCipherSuites());
                hos.putBytes8(compressionMethod);
                extensions.send(hos);       // In TLS 1.3, use of certain
                                            // extensions is mandatory.
            } catch (IOException ioe) {
                // unlikely
            }

            return hos.toByteArray();
        }

        // (D)TLS 1.3, for cookie generation.
        byte[] getHeaderBytes() {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            try {
                // copied from send() method
                hos.putInt8((byte)((clientVersion >>> 8) & 0xFF));
                hos.putInt8((byte)(clientVersion & 0xFF));
                hos.write(clientRandom.randomBytes, 0, 32);
                hos.putBytes8(sessionId.getId());
                hos.putBytes16(getEncodedCipherSuites());
                hos.putBytes8(compressionMethod);
            } catch (IOException ioe) {
                // unlikely
            }

            return hos.toByteArray();
        }

        private static int[] getCipherSuiteIds(
                List<CipherSuite> cipherSuites) {
            if (cipherSuites != null) {
                int[] ids = new int[cipherSuites.size()];
                int i = 0;
                for (CipherSuite cipherSuite : cipherSuites) {
                    ids[i++] = cipherSuite.id;
                }

                return ids;
            }

            return new int[0];
        }

        private static List<CipherSuite> getCipherSuites(int[] ids) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (int id : ids) {
                CipherSuite cipherSuite = CipherSuite.valueOf(id);
                if (cipherSuite != null) {
                    cipherSuites.add(cipherSuite);
                }
            }

            return Collections.unmodifiableList(cipherSuites);
        }

        private List<String> getCipherSuiteNames() {
            List<String> names = new LinkedList<>();
            for (int id : cipherSuiteIds) {
                names.add(CipherSuite.nameOf(id) +
                        "(" + Utilities.byte16HexString(id) + ")");            }

            return names;
        }

        private byte[] getEncodedCipherSuites() {
            byte[] encoded = new byte[cipherSuiteIds.length << 1];
            int i = 0;
            for (int id : cipherSuiteIds) {
                encoded[i++] = (byte)(id >> 8);
                encoded[i++] = (byte)id;
            }
            return encoded;
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_HELLO;
        }

        @Override
        public int messageLength() {
            /*
             * Add fixed size parts of each field...
             * version + random + session + cipher + compress
             */
            return (2 + 32 + 1 + 2 + 1
                + sessionId.length()        /* ... + variable parts */
                + (isDTLS ? (1 + cookie.length) : 0)
                + (cipherSuiteIds.length * 2)
                + compressionMethod.length)
                + extensions.length();      // In TLS 1.3, use of certain
                                            // extensions is mandatory.
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            sendCore(hos);
            extensions.send(hos);       // In TLS 1.3, use of certain
                                        // extensions is mandatory.
        }

        void sendCore(HandshakeOutStream hos) throws IOException {
            hos.putInt8((byte) (clientVersion >>> 8));
            hos.putInt8((byte) clientVersion);
            hos.write(clientRandom.randomBytes, 0, 32);
            hos.putBytes8(sessionId.getId());
            if (isDTLS) {
                hos.putBytes8(cookie);
            }
            hos.putBytes16(getEncodedCipherSuites());
            hos.putBytes8(compressionMethod);
        }

        public byte[] toByteArray() throws IOException {
            byte[] hb = getHeaderBytes();
            HandshakeOutStream hos = new HandshakeOutStream(null);
            this.extensions.send(hos);
            byte[] eb = hos.toByteArray();
            byte[] answer = new byte[hb.length+ eb.length];
            System.arraycopy(hb, 0, answer, 0, hb.length);
            System.arraycopy(eb, 0, answer, hb.length, eb.length);
            return answer;
        }

        public byte[] getEncodedByteArray() throws IOException {
            HandshakeOutStream hos = new HandshakeOutStream(null);
            hos.putInt8((byte) ((clientVersion >>> 8) & 0xFF));
            hos.putInt8((byte) (clientVersion & 0xFF));
            hos.write(clientRandom.randomBytes, 0, 32);
            hos.putBytes16(getEncodedCipherSuites());
            hos.putBytes8(compressionMethod);
            this.extensions.sendCompressed(hos);
            return hos.toByteArray();
        }

        @Override
        public String toString() {
            MessageFormat messageFormat;
            Object[] messageFields;
            if (isDTLS) {
                messageFormat = new MessageFormat(
                        """
                                "ClientHello": '{'
                                  "client version"      : "{0}",
                                  "random"              : "{1}",
                                  "session id"          : "{2}",
                                  "cookie"              : "{3}",
                                  "cipher suites"       : "{4}",
                                  "compression methods" : "{5}",
                                  "extensions"          : [
                                {6}
                                  ]
                                '}'""",
                        Locale.ENGLISH);
                messageFields = new Object[]{
                        ProtocolVersion.nameOf(clientVersion),
                        Utilities.toHexString(clientRandom.randomBytes),
                        sessionId.toString(),
                        Utilities.toHexString(cookie),
                        getCipherSuiteNames().toString(),
                        Utilities.toHexString(compressionMethod),
                        Utilities.indent(Utilities.indent(extensions.toString()))
                };

            } else {
                messageFormat = new MessageFormat(
                        """
                                "ClientHello": '{'
                                  "client version"      : "{0}",
                                  "random"              : "{1}",
                                  "session id"          : "{2}",
                                  "cipher suites"       : "{3}",
                                  "compression methods" : "{4}",
                                  "extensions"          : [
                                {5}
                                  ]
                                '}'""",
                        Locale.ENGLISH);
                messageFields = new Object[]{
                        ProtocolVersion.nameOf(clientVersion),
                        Utilities.toHexString(clientRandom.randomBytes),
                        sessionId.toString(),
                        getCipherSuiteNames().toString(),
                        Utilities.toHexString(compressionMethod),
                        Utilities.indent(Utilities.indent(extensions.toString()))
                };

            }
            return messageFormat.format(messageFields);
        }

    }

    /**
     * The "ClientHello" handshake message kick-start producer.
     */
    private static final
            class ClientHelloKickstartProducer implements SSLProducer {
        
        private ECHConfig echConfig;
        private PublicKey ephemeralPub;
        // Prevent instantiation of this class.
        private ClientHelloKickstartProducer() {
            // blank
        }

        // Produce kickstart handshake message.
        @Override
        public byte[] produce(ConnectionContext context) throws IOException {
            // The producing happens in client side only.
            byte[] echConfigBytes = Files.readAllBytes(Path.of("/tmp/ech.conf"));
            this.echConfig = new ECHConfig(echConfigBytes);
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // clean up this producer
            chc.handshakeProducers.remove(SSLHandshake.CLIENT_HELLO.id);

            // session ID of the ClientHello message
            SessionId sessionId = new SessionId(new byte[0]);

            // a list of cipher suites sent by the client
            List<CipherSuite> cipherSuites = chc.activeCipherSuites;

            //
            // Try to resume an existing session.
            //
            SSLSessionContextImpl ssci = (SSLSessionContextImpl)
                    chc.sslContext.engineGetClientSessionContext();
            SSLSessionImpl session = ssci.get(
                    chc.conContext.transport.getPeerHost(),
                    chc.conContext.transport.getPeerPort());
            if (session != null) {
                // If unsafe server certificate change is not allowed, reserve
                // current server certificates if the previous handshake is a
                // session-resumption abbreviated initial handshake.
                if (!ClientHandshakeContext.allowUnsafeServerCertChange &&
                        session.isSessionResumption()) {
                    try {
                        // If existing, peer certificate chain cannot be null.
                        chc.reservedServerCerts =
                            (X509Certificate[])session.getPeerCertificates();
                    } catch (SSLPeerUnverifiedException puve) {
                        // Maybe not certificate-based, ignore the exception.
                    }
                }

                if (!session.isRejoinable()) {
                    session = null;
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, the session is not rejoinable");
                    }
                }
            }

            CipherSuite sessionSuite = null;
            if (session != null) {
                sessionSuite = session.getSuite();
                if (!chc.isNegotiable(sessionSuite)) {
                    session = null;
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, unavailable session cipher suite");
                    }
                }
            }

            ProtocolVersion sessionVersion = null;
            if (session != null) {
                sessionVersion = session.getProtocolVersion();
                if (!chc.isNegotiable(sessionVersion)) {
                    session = null;
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, unavailable protocol version");
                    }
                }
            }

            if (session != null &&
                !sessionVersion.useTLS13PlusSpec() &&
                SSLConfiguration.useExtendedMasterSecret) {

                boolean isEmsAvailable = chc.sslConfig.isAvailable(
                        SSLExtension.CH_EXTENDED_MASTER_SECRET, sessionVersion);
                if (isEmsAvailable && !session.useExtendedMasterSecret &&
                        !SSLConfiguration.allowLegacyResumption) {
                    // perform full handshake instead
                    //
                    // The client SHOULD NOT offer an abbreviated handshake
                    // to resume a session that does not use an extended
                    // master secret.  Instead, it SHOULD offer a full
                    // handshake.
                     session = null;
                }

                if ((session != null) &&
                        !ClientHandshakeContext.allowUnsafeServerCertChange) {
                    // It is fine to move on with abbreviate handshake if
                    // endpoint identification is enabled.
                    String identityAlg = chc.sslConfig.identificationProtocol;
                    if (identityAlg == null || identityAlg.isEmpty()) {
                        if (isEmsAvailable) {
                            if (!session.useExtendedMasterSecret) {
                                // perform full handshake instead
                                session = null;
                            }   // Otherwise, use extended master secret.
                        } else {
                            // The extended master secret extension does not
                            // apply to SSL 3.0.  Perform a full handshake
                            // instead.
                            //
                            // Note that the useExtendedMasterSecret is
                            // extended to protect SSL 3.0 connections,
                            // by discarding abbreviate handshake.
                            session = null;
                        }
                    }
                }
            }

            // ensure that the endpoint identification algorithm matches the
            // one in the session
            String identityAlg = chc.sslConfig.identificationProtocol;
            if (session != null && identityAlg != null) {
                String sessionIdentityAlg =
                    session.getIdentificationProtocol();
                if (!identityAlg.equalsIgnoreCase(sessionIdentityAlg)) {
                    if (SSLLogger.isOn &&
                    SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest("Can't resume, endpoint id" +
                            " algorithm does not match, requested: " +
                            identityAlg + ", cached: " + sessionIdentityAlg);
                    }
                    session = null;
                }
            }

            if (session != null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest("Try resuming session", session);
                }

                // only set session id if session is 1.2 or earlier
                if (!session.getProtocolVersion().useTLS13PlusSpec()) {
                    sessionId = session.getSessionId();
                }

                // If no new session is allowed, force use of the previous
                // session ciphersuite, and add the renegotiation SCSV if
                // necessary.
                if (!chc.sslConfig.enableSessionCreation) {
                    if (!chc.conContext.isNegotiated &&
                        !sessionVersion.useTLS13PlusSpec() &&
                        cipherSuites.contains(
                            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
                        cipherSuites = Arrays.asList(sessionSuite,
                            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                    } else {    // otherwise, use renegotiation_info extension
                        cipherSuites = List.of(sessionSuite);
                    }

                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "No new session is allowed, so try to resume " +
                            "the session cipher suite only", sessionSuite);
                    }
                }

                chc.isResumption = true;
                chc.resumingSession = session;
            }

            if (session == null) {
                if (!chc.sslConfig.enableSessionCreation) {
                    throw new SSLHandshakeException(
                            "No new session is allowed and " +
                            "no existing session can be resumed");
                }
            }
            if (sessionId.length() == 0 &&
                    chc.maximumActiveProtocol.useTLS13PlusSpec() &&
                    SSLConfiguration.useCompatibilityMode) {
                // In compatibility mode, the TLS 1.3 legacy_session_id
                // field MUST be non-empty, so a client not offering a
                // pre-TLS 1.3 session MUST generate a new 32-byte value.
                sessionId =
                        new SessionId(true, chc.sslContext.getSecureRandom());
            }

            ProtocolVersion minimumVersion = ProtocolVersion.NONE;
            for (ProtocolVersion pv : chc.activeProtocols) {
                if (minimumVersion == ProtocolVersion.NONE ||
                        pv.compare(minimumVersion) < 0) {
                    minimumVersion = pv;
                }
            }

            // exclude SCSV for secure renegotiation
            if (!minimumVersion.useTLS13PlusSpec()) {
                if (chc.conContext.secureRenegotiation &&
                        cipherSuites.contains(
                            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
                    // The cipherSuites may be unmodifiable
                    cipherSuites = new LinkedList<>(cipherSuites);
                    cipherSuites.remove(
                            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                }
            }

            // make sure there is a negotiable cipher suite.
            boolean negotiable = false;
            for (CipherSuite suite : cipherSuites) {
                if (chc.isNegotiable(suite)) {
                    negotiable = true;
                    break;
                }
            }
            if (!negotiable) {
                throw new SSLHandshakeException("No negotiable cipher suite");
            }

            // Create the handshake message.
            ProtocolVersion clientHelloVersion = chc.maximumActiveProtocol;
            if (clientHelloVersion.useTLS13PlusSpec()) {
                // In (D)TLS 1.3, the client indicates its version preferences
                // in the "supported_versions" extension and the client_version
                // (legacy_version) field MUST be set to (D)TLS 1.2.
                if (clientHelloVersion.isDTLS) {
                    clientHelloVersion = ProtocolVersion.DTLS12;
                } else {
                    clientHelloVersion = ProtocolVersion.TLS12;
                }
            }

            ClientHelloMessage chm = new ClientHelloMessage(chc,
                    clientHelloVersion.id, sessionId, cipherSuites,
                    chc.sslContext.getSecureRandom());

            ClientHelloMessage innerChm = new ClientHelloMessage(chc,
                    clientHelloVersion.id, sessionId, cipherSuites,
                    chc.sslContext.getSecureRandom());

            // cache the client random number for further using
            chc.clientHelloRandom = chm.clientRandom;
            chc.clientHelloVersion = clientHelloVersion.id;

            // Produce extensions for ClientHello handshake message.
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(
                    SSLHandshake.CLIENT_HELLO, chc.activeProtocols);
SSLLogger.fine("Now produce extensions", chc);
            chm.extensions.produce(chc, extTypes);
            for (SSLExtension ext: extTypes) {
            }
            innerChm.extensions.produce(chc, extTypes);
            byte[] innerBytes = innerChm.toByteArray();
            int cl = innerBytes.length;
            byte[] innerCh = new byte[cl+4];
            System.arraycopy(innerBytes, 0, innerCh, 4, cl);
            innerCh[0] = 0x1;
            int clw = cl;
            innerCh[3] = (byte)(clw %256);
            clw = clw/256;
            innerCh[2] = (byte)(clw % 256);
            innerCh[1] = (byte)(clw / 256);
SSLLogger.info("inner CH ("+(cl+4)+"): ", innerCh);
byte[] crb = innerChm.clientRandom.randomBytes;
SSLLogger.info("inner, client_random ("+crb.length+")", crb);
byte[] isid = innerChm.sessionId.getId();
SSLLogger.info("inner, session_id ("+isid.length+")", isid);
byte[] clear = innerChm.getEncodedByteArray();
SSLLogger.info("encoded inner CH ", clear);

SSLLogger.info("outer, client_random ("+crb.length+")", chm.clientRandom.randomBytes);
SSLLogger.info("outer, session_id", chm.sessionId.getId());


SSLLogger.info("selected version: "+echConfig.getVersion()+", configid = "+echConfig.getConfigId());
SSLLogger.info("peer pub: ", echConfig.getPublicKey());

        int innersnipadding = 0;
        int lengthWithSniPadding = innersnipadding + clear.length;
        int lengthOfPadding = 31 - ((lengthWithSniPadding - 1) % 32);
        int lengthWithPadding = clear.length + lengthOfPadding + innersnipadding;
        while (lengthWithPadding < OSSL_ECH_PADDING_TARGET) {
            lengthWithPadding += OSSL_ECH_PADDING_INCREMENT;
        }
            int clearLen = lengthWithPadding;
            SSLLogger.info("EAAE: padding: mnl " + echConfig.getMaxNameLength() + ", lws: " + lengthWithSniPadding
                    + ",lop: " + lengthOfPadding + ", lwp: " + lengthWithPadding
                    + ", clear_len: " + clearLen + ", orig: " + clear.length);
            SSLLogger.info("Raw ECHConfig: ", echConfig.getRaw());
            byte[] info = makeInfo();
            SSLLogger.info("info", info);
            PublicKey peerPub = convertPeerPublicKey(echConfig.getPublicKey());
            byte[] sharedKey = encapsulateKey(chc, peerPub);
            System.err.println("sk = "+sharedKey);
            SSLLogger.info("SharedKey", sharedKey);
            
            byte[] pkt = chm.toByteArray();
            SSLLogger.info("pkt0", pkt);
            int cipherlen = clearLen + 16; // not valid for all AEAD
            int oldlen = pkt.length;
            pkt = expandOuterCH(pkt, this.ephemeralPub.getEncoded(), cipherlen);
            int cipherStart = pkt.length - cipherlen;
            SSLLogger.info("pkt", pkt);
            byte[] aad = new byte[pkt.length - 4];
            System.arraycopy(pkt,0, aad,0, aad.length);
            byte[] cipher = encrypt(sharedKey, aad, clear);
            byte[] newCH = new byte[pkt.length - oldlen+1];
            System.arraycopy(pkt, oldlen-1, newCH, 0, newCH.length);
          //  System.arraycopy(cipher, 0, pkt, cipherStart, cipher.length);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ClientHello handshake message", chm);
            }
            chm.extensions.updateExtension(SSLExtension.CH_ECH, newCH);
            // Output the handshake message.
            chm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            // Reserve the initial ClientHello message for the follow-on
            // cookie exchange if needed.
            chc.initialClientHelloMsg = chm;

            // What's the expected response?
            chc.handshakeConsumers.put(
                    SSLHandshake.SERVER_HELLO.id, SSLHandshake.SERVER_HELLO);
            if (chc.sslContext.isDTLS() &&
                    !minimumVersion.useTLS13PlusSpec()) {
                chc.handshakeConsumers.put(
                        SSLHandshake.HELLO_VERIFY_REQUEST.id,
                        SSLHandshake.HELLO_VERIFY_REQUEST);
            }

            // The handshake message has been delivered.
            return null;
        }

        private byte[] makeInfo() {
            byte[] oecb = OSSL_ECH_CONTEXT_STRING.getBytes();
            byte[] info = new byte[oecb.length + 1 + echConfig.getRaw().length];
            System.arraycopy(oecb, 0, info, 0, oecb.length);
            info[oecb.length] = 0;
            System.arraycopy(echConfig.getRaw(), 0, info, oecb.length + 1, echConfig.getRaw().length);
            return info;
        }
    
        private PublicKey convertPeerPublicKey(byte[] uBytes) throws IOException {
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

        private byte[] encapsulateKey(ClientHandshakeContext chc, PublicKey peerPub) throws IOException {
            try {
                SSLLogger.info("START ENCAPSULATING KEY", peerPub);
                NamedGroup ng = NamedGroup.X25519;
                System.err.println("alg = " + ng.algorithm);
                byte[] ikme = HexFormat.of().parseHex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
SSLLogger.info("IKME: "+ikme.length, ikme);
//                NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
//                KeyFactory kf = KeyFactory.getInstance("XDH");
//                KeySpec privateSpec = new XECPrivateKeySpec(paramSpec, ikme);
//                PrivateKey aPrivate = kf.generatePrivate(privateSpec);
//SSLLogger.info("ENCODED: " , aPrivate.getEncoded());
                deriveKeyPair(ikme);
                
                
                
                
                
                KeyPairGenerator kpg
                        = KeyPairGenerator.getInstance(ng.algorithm);
              //  IvParameterSpec ivParameterSpec = new IvParameterSpec(ikme);
              //  kpg.initialize(ivParameterSpec);
                KeyPair kp = kpg.generateKeyPair();
         //       PrivateKey aPrivate = kp.getPrivate();
                XECPublicKey xpk = (XECPublicKey) kp.getPublic();
           //     SSLLogger.info("GOTFIRSTKEY", aPrivate, xpk);
                
                
                SSLKeyExchange ke = SSLKeyExchange.valueOf(ng);
                System.err.println("KeyExchange class = "+ke.getClass());
                SSLPossession[] sslpos = ke.createPossessions(chc);
                System.err.println("sslpos length = "+sslpos.length);
                SSLLogger.info("SSLPOSSS", sslpos[0]);
                NamedGroupPossession ngp = (NamedGroupPossession)sslpos[0];
                SSLLogger.info("public bytes = ", ngp.encode());
                SSLLogger.info("pubkey = ", ngp.getPublicKey());
                this.ephemeralPub = ngp.getPublicKey();
                System.err.println("PKclass = "+ngp.getPublicKey().getClass());
                SSLLogger.info("private key = ", ngp.getPrivateKey());
                KAKeyDerivation kd = new KAKeyDerivation(ng.algorithm,chc, ngp.getPrivateKey(),peerPub);
                SSLLogger.info("KEYderivation = ", kd);
                System.err.println("1");
                KeyAgreement ka = KeyAgreement.getInstance(ng.algorithm);
                System.err.println("2");
                ka.init(ngp.getPrivateKey());
                System.err.println("3");
                Key sharedKey = ka.doPhase(peerPub, true);
                System.err.println("4");
                byte[] dh = ka.generateSecret();
                System.err.println("sharedkey = "+sharedKey);
                byte[] kemContext = new byte[64];
                System.arraycopy(this.ephemeralPub.getEncoded(), 0, kemContext, 0, 32);
                System.arraycopy(peerPub.getEncoded(), 0, kemContext, 32, 32);
                byte[] answer = extractAndExpand(dh, kemContext);
                return answer;
            } catch (Exception  ex) {
                ex.printStackTrace();
throw new IOException (ex);
            }
        }
        
        private byte[] expandOuterCH(byte[] src, byte[] mypub, int cipherlen) {
            System.err.println("expand, src size = " + src.length);
            byte KDF_HI = 0x0; //should come from EchConfig
            byte KDF_LO = 0x1;
            byte AEAD_HI = 0x0;
            byte AEAD_LO = 0x1;
            int ol = src.length-3; // remove encrypted_client_hello length + 00
            int will_add = 43;
            int ef0dlength=1 + 4 + 1 + 2 + mypub.length+2+cipherlen;
            byte[] answer = new byte[ol+will_add+cipherlen];
            System.arraycopy(src, 0, answer, 0, ol);
            answer[ol] = (byte)(ef0dlength/256);
            answer[ol+1] = (byte) (ef0dlength%256);
            answer[ol+2] = 0x0; // ECHClientHelloType.outer
            answer[ol + 3] = KDF_HI;
            answer[ol + 4] = KDF_LO;
            answer[ol + 5] = AEAD_HI;
            answer[ol + 6] = AEAD_LO;
            answer[ol+7] = 0x0; // config id
            answer[ol+8] = 0x0; // config id
            answer[ol+9] = 0x20; // length mypub
            System.arraycopy(mypub, 0, answer, ol+9, 32);
            answer[ol+40] = (byte)(cipherlen/256);
            answer[ol+41] = (byte)(cipherlen%256);
            for (int i = 0; i < cipherlen; i++) {
                answer[ol+will_add+i] = 0x0;
            }
            return answer;
        }
       
        byte[] encrypt(byte[] key, byte[] aad, byte[] clear) {
            try {
                // we assume aeadId = 0x0001 which is AES-GCM-128
                final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, new byte[0]); //128 bit auth tag length
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
                System.err.println("Got cipher: " + cipher);
                byte[] fin = cipher.doFinal(clear);
                byte[] answer = new byte[clear.length + 16];
                System.arraycopy(fin, 0, answer, 0, fin.length);
                return answer;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                ex.printStackTrace();
            } catch (InvalidKeyException ex) {
                ex.printStackTrace();
            } catch (InvalidAlgorithmParameterException ex) {
                ex.printStackTrace();
            }
            return null;
        }
    }

    private static final
            class ClientHelloProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private ClientHelloProducer() {
            // blank
        }

        // Response to one of the following handshake message:
        //     HelloRequest                     (SSL 3.0/TLS 1.0/1.1/1.2)
        //     ServerHello(HelloRetryRequest)   (TLS 1.3)
        //     HelloVerifyRequest               (DTLS 1.0/1.2)
        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            SSLHandshake ht = message.handshakeType();
            if (ht == null) {
                throw new UnsupportedOperationException("Not supported yet.");
            }

            switch (ht) {
                case HELLO_REQUEST:
                    // SSL 3.0/TLS 1.0/1.1/1.2
                    try {
                        chc.kickstart();
                    } catch (IOException ioe) {
                        throw chc.conContext.fatal(
                                Alert.HANDSHAKE_FAILURE, ioe);
                    }

                    // The handshake message has been delivered.
                    return null;
                case HELLO_VERIFY_REQUEST:
                    // DTLS 1.0/1.2
                    //
                    // The HelloVerifyRequest consumer should have updated the
                    // ClientHello handshake message with cookie.
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                            "Produced ClientHello(cookie) handshake message",
                            chc.initialClientHelloMsg);
                    }

                    // Output the handshake message.
                    chc.initialClientHelloMsg.write(chc.handshakeOutput);
                    chc.handshakeOutput.flush();

                    // What's the expected response?
                    chc.handshakeConsumers.put(SSLHandshake.SERVER_HELLO.id,
                            SSLHandshake.SERVER_HELLO);

                    ProtocolVersion minimumVersion = ProtocolVersion.NONE;
                    for (ProtocolVersion pv : chc.activeProtocols) {
                        if (minimumVersion == ProtocolVersion.NONE ||
                                pv.compare(minimumVersion) < 0) {
                            minimumVersion = pv;
                        }
                    }
                    if (chc.sslContext.isDTLS() &&
                            !minimumVersion.useTLS13PlusSpec()) {
                        chc.handshakeConsumers.put(
                                SSLHandshake.HELLO_VERIFY_REQUEST.id,
                                SSLHandshake.HELLO_VERIFY_REQUEST);
                    }

                    // The handshake message has been delivered.
                    return null;
                case HELLO_RETRY_REQUEST:
                    // TLS 1.3
                    // The HelloRetryRequest consumer should have updated the
                    // ClientHello handshake message with cookie.
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine(
                            "Produced ClientHello(HRR) handshake message",
                            chc.initialClientHelloMsg);
                    }

                    // Output the handshake message.
                    chc.initialClientHelloMsg.write(chc.handshakeOutput);
                    chc.handshakeOutput.flush();

                    // What's the expected response?
                    chc.conContext.consumers.putIfAbsent(
                            ContentType.CHANGE_CIPHER_SPEC.id,
                            ChangeCipherSpec.t13Consumer);
                    chc.handshakeConsumers.put(SSLHandshake.SERVER_HELLO.id,
                            SSLHandshake.SERVER_HELLO);

                    // The handshake message has been delivered.
                    return null;
                default:
                    throw new UnsupportedOperationException(
                            "Not supported yet.");
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer.
     */
    private static final class ClientHelloConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // clean up this consumer
            shc.handshakeConsumers.remove(SSLHandshake.CLIENT_HELLO.id);
            if (!shc.handshakeConsumers.isEmpty()) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "No more handshake message allowed " +
                        "in a ClientHello flight");
            }

            // Get enabled extension types in ClientHello handshake message.
            SSLExtension[] enabledExtensions =
                    shc.sslConfig.getEnabledExtensions(
                            SSLHandshake.CLIENT_HELLO);

            ClientHelloMessage chm =
                    new ClientHelloMessage(shc, message, enabledExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ClientHello handshake message", chm);
            }

            shc.clientHelloVersion = chm.clientVersion;
            onClientHello(shc, chm);
        }

        private void onClientHello(ServerHandshakeContext context,
                ClientHelloMessage clientHello) throws IOException {
            // Negotiate protocol version.
            //
            // Check and launch SupportedVersions.
            SSLExtension[] extTypes = new SSLExtension[] {
                    SSLExtension.CH_SUPPORTED_VERSIONS
                };
            clientHello.extensions.consumeOnLoad(context, extTypes);

            ProtocolVersion negotiatedProtocol;
            CHSupportedVersionsSpec svs =
                    (CHSupportedVersionsSpec)context.handshakeExtensions.get(
                            SSLExtension.CH_SUPPORTED_VERSIONS);
            if (svs != null) {
                negotiatedProtocol =
                        negotiateProtocol(context, svs.requestedProtocols);
            } else {
                negotiatedProtocol =
                        negotiateProtocol(context, clientHello.clientVersion);
            }
            context.negotiatedProtocol = negotiatedProtocol;
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Negotiated protocol version: " + negotiatedProtocol.name);
            }

            // Consume the handshake message for the specific protocol version.
            if (negotiatedProtocol.isDTLS) {
                if (negotiatedProtocol.useTLS13PlusSpec()) {
                    d13HandshakeConsumer.consume(context, clientHello);
                } else {
                    d12HandshakeConsumer.consume(context, clientHello);
                }
            } else {
                if (negotiatedProtocol.useTLS13PlusSpec()) {
                    t13HandshakeConsumer.consume(context, clientHello);
                } else {
                    t12HandshakeConsumer.consume(context, clientHello);
                }
            }
        }

        // Select a protocol version according to the
        // ClientHello.client_version.
        private ProtocolVersion negotiateProtocol(
                ServerHandshakeContext context,
                int clientHelloVersion) throws SSLException {

            // Per TLS 1.3 specification, server MUST negotiate TLS 1.2 or prior
            // even if ClientHello.client_version is 0x0304 or later.
            int chv = clientHelloVersion;
            if (context.sslContext.isDTLS()) {
                if (chv < ProtocolVersion.DTLS12.id) {
                    chv = ProtocolVersion.DTLS12.id;
                }
            } else {
                if (chv > ProtocolVersion.TLS12.id) {
                    chv = ProtocolVersion.TLS12.id;
                }
            }

            // Select a protocol version from the activated protocols.
            ProtocolVersion pv = ProtocolVersion.selectedFrom(
                    context.activeProtocols, chv);
            if (pv == null || pv == ProtocolVersion.NONE ||
                    pv == ProtocolVersion.SSL20Hello) {
                throw context.conContext.fatal(Alert.PROTOCOL_VERSION,
                    "Client requested protocol " +
                    ProtocolVersion.nameOf(clientHelloVersion) +
                    " is not enabled or supported in server context");
            }

            return pv;
        }

        // Select a protocol version according to the
        // supported_versions extension.
        private ProtocolVersion negotiateProtocol(
                ServerHandshakeContext context,
                int[] clientSupportedVersions) throws SSLException {

            // The client supported protocol versions are present in client
            // preference order.  This implementation chooses to use the server
            // preference of protocol versions instead.
            for (ProtocolVersion spv : context.activeProtocols) {
                if (spv == ProtocolVersion.SSL20Hello) {
                    continue;
                }
                for (int cpv : clientSupportedVersions) {
                    if (cpv == ProtocolVersion.SSL20Hello.id) {
                        continue;
                    }
                    if (spv.id == cpv) {
                        return spv;
                    }
                }
            }

            // No protocol version can be negotiated.
            throw context.conContext.fatal(Alert.PROTOCOL_VERSION,
                "The client supported protocol versions " + Arrays.toString(
                    ProtocolVersion.toStringArray(clientSupportedVersions)) +
                " are not accepted by server preferences " +
                context.activeProtocols);
        }
    }

    /**
     * The "ClientHello" handshake message consumer for TLS 1.2 and
     * prior SSL/TLS protocol versions.
     */
    private static final
            class T12ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private T12ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHelloMessage clientHello = (ClientHelloMessage)message;

            //
            // validate
            //

            // Reject client initiated renegotiation?
            //
            // If server side should reject client-initiated renegotiation,
            // send an Alert.HANDSHAKE_FAILURE fatal alert, not a
            // no_renegotiation warning alert (no_renegotiation must be a
            // warning: RFC 2246).  no_renegotiation might seem more
            // natural at first, but warnings are not appropriate because
            // the sending party does not know how the receiving party
            // will behave.  This state must be treated as a fatal server
            // condition.
            //
            // This will not have any impact on server initiated renegotiation.
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation &&
                        !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsafe renegotiation is not allowed");
                }

                if (ServerHandshakeContext.rejectClientInitiatedRenego &&
                        !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Client initiated renegotiation is not allowed");
                }
            }

            // Consume a Session Ticket Extension if it exists
            SSLExtension[] ext = new SSLExtension[]{
                    SSLExtension.CH_SESSION_TICKET
            };
            clientHello.extensions.consumeOnLoad(shc, ext);

            // Does the client want to resume a session?
            if (clientHello.sessionId.length() != 0 || shc.statelessResumption) {
                SSLSessionContextImpl cache = (SSLSessionContextImpl)shc.sslContext
                        .engineGetServerSessionContext();

                SSLSessionImpl previous;
                // Use the stateless session ticket if provided
                if (shc.statelessResumption) {
                    previous = shc.resumingSession;
                } else {
                    previous = cache.get(clientHello.sessionId.getId());
                }

                boolean resumingSession =
                        (previous != null) && previous.isRejoinable();
                if (!resumingSession) {
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                                "Can't resume, " +
                                "the existing session is not rejoinable");
                    }
                }
                // Validate the negotiated protocol version.
                if (resumingSession) {
                    ProtocolVersion sessionProtocol =
                            previous.getProtocolVersion();
                    if (sessionProtocol != shc.negotiatedProtocol) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                "Can't resume, not the same protocol version");
                        }
                    }
                }

                // Validate the required client authentication.
                if (resumingSession &&
                    (shc.sslConfig.clientAuthType == CLIENT_AUTH_REQUIRED)) {
                    try {
                        previous.getPeerPrincipal();
                    } catch (SSLPeerUnverifiedException e) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                "Can't resume, " +
                                "client authentication is required");
                        }
                    }
                }

                // Validate that the cached cipher suite.
                if (resumingSession) {
                    CipherSuite suite = previous.getSuite();
                    if ((!shc.isNegotiable(suite)) ||
                            (!clientHello.cipherSuites.contains(suite))) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                "Can't resume, " +
                                "the session cipher suite is absent");
                        }
                    }
                }

                // ensure that the endpoint identification algorithm matches the
                // one in the session
                String identityAlg = shc.sslConfig.identificationProtocol;
                if (resumingSession && identityAlg != null) {
                    String sessionIdentityAlg =
                        previous.getIdentificationProtocol();
                    if (!identityAlg.equalsIgnoreCase(sessionIdentityAlg)) {
                        if (SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, endpoint id" +
                            " algorithm does not match, requested: " +
                            identityAlg + ", cached: " + sessionIdentityAlg);
                        }
                        resumingSession = false;
                    }
                }

                // So far so good.  Note that the handshake extensions may reset
                // the resuming options later.
                shc.isResumption = resumingSession;
                shc.resumingSession = resumingSession ? previous : null;

                if (!resumingSession && SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Session not resumed.");
                }
            }

            // cache the client random number for further using
            shc.clientHelloRandom = clientHello.clientRandom;

            // Check and launch ClientHello extensions.
            SSLExtension[] extTypes = shc.sslConfig.getExclusiveExtensions(
                    SSLHandshake.CLIENT_HELLO,
                    List.of(SSLExtension.CH_SESSION_TICKET));
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only need to ServerHello, which may add more responders later.
            // Note that ServerHello and HelloRetryRequest share the same
            // handshake type/id.  The ServerHello producer may be replaced
            // by HelloRetryRequest producer if needed.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                    SSLHandshake.SERVER_HELLO);

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_STATUS,
                SSLHandshake.SERVER_KEY_EXCHANGE,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.SERVER_HELLO_DONE,

                // abbreviated handshake messages
                SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer for TLS 1.3.
     */
    private static final
            class T13ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private T13ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHelloMessage clientHello = (ClientHelloMessage)message;

            // [RFC 8446] TLS 1.3 forbids renegotiation. If a server has
            // negotiated TLS 1.3 and receives a ClientHello at any other
            // time, it MUST terminate the connection with an
            // "unexpected_message" alert.
            if (shc.conContext.isNegotiated) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Received unexpected renegotiation handshake message");
            }

            if (clientHello.clientVersion != ProtocolVersion.TLS12.id) {
                throw shc.conContext.fatal(Alert.PROTOCOL_VERSION,
                        "The ClientHello.legacy_version field is not TLS 1.2");
            }

            // The client may send a dummy change_cipher_spec record
            // immediately after the first ClientHello.
            shc.conContext.consumers.putIfAbsent(
                    ContentType.CHANGE_CIPHER_SPEC.id,
                    ChangeCipherSpec.t13Consumer);

            // Is it a resumption?
            //
            // Check and launch the "psk_key_exchange_modes" and
            // "pre_shared_key" extensions first, which will reset the
            // resuming session, no matter the extensions present or not.
            shc.isResumption = true;
            SSLExtension[] extTypes = new SSLExtension[] {
                    SSLExtension.PSK_KEY_EXCHANGE_MODES,
                    SSLExtension.CH_PRE_SHARED_KEY
                };
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            // Check and launch ClientHello extensions other than
            // "psk_key_exchange_modes", "pre_shared_key", "protocol_version"
            // and "key_share" extensions.
            //
            // These extensions may discard session resumption, or ask for
            // hello retry.
            extTypes = shc.sslConfig.getExclusiveExtensions(
                    SSLHandshake.CLIENT_HELLO,
                    Arrays.asList(
                            SSLExtension.PSK_KEY_EXCHANGE_MODES,
                            SSLExtension.CH_PRE_SHARED_KEY,
                            SSLExtension.CH_SUPPORTED_VERSIONS));
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            if (!shc.handshakeProducers.isEmpty()) {
                // Should be HelloRetryRequest producer.
                goHelloRetryRequest(shc, clientHello);
            } else {
                goServerHello(shc, clientHello);
            }
        }

        private void goHelloRetryRequest(ServerHandshakeContext shc,
                ClientHelloMessage clientHello) throws IOException {
            HandshakeProducer handshakeProducer =
                    shc.handshakeProducers.remove(
                            SSLHandshake.HELLO_RETRY_REQUEST.id);
            if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, clientHello);
            } else {
                // unlikely
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "No HelloRetryRequest producer: " + shc.handshakeProducers);
            }

            if (!shc.handshakeProducers.isEmpty()) {
                // unlikely, but please double-check.
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "unknown handshake producers: " + shc.handshakeProducers);
            }
        }

        private void goServerHello(ServerHandshakeContext shc,
                ClientHelloMessage clientHello) throws IOException {
            //
            // validate
            //
            shc.clientHelloRandom = clientHello.clientRandom;

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only ServerHello/HelloRetryRequest producer, which adds
            // more responders later.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                SSLHandshake.SERVER_HELLO);

            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.ENCRYPTED_EXTENSIONS,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_VERIFY,
                SSLHandshake.FINISHED
            };

            //
            // produce
            //
            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, clientHello);
                }
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer for DTLS 1.2 and
     * previous DTLS protocol versions.
     */
    private static final
            class D12ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private D12ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHelloMessage clientHello = (ClientHelloMessage)message;

            //
            // validate
            //

            // Reject client initiated renegotiation?
            //
            // If server side should reject client-initiated renegotiation,
            // send an Alert.HANDSHAKE_FAILURE fatal alert, not a
            // no_renegotiation warning alert (no_renegotiation must be a
            // warning: RFC 2246).  no_renegotiation might seem more
            // natural at first, but warnings are not appropriate because
            // the sending party does not know how the receiving party
            // will behave.  This state must be treated as a fatal server
            // condition.
            //
            // This will not have any impact on server initiated renegotiation.
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation &&
                        !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsafe renegotiation is not allowed");
                }

                if (ServerHandshakeContext.rejectClientInitiatedRenego &&
                        !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Client initiated renegotiation is not allowed");
                }
            }


            // Does the client want to resume a session?
            if (clientHello.sessionId.length() != 0) {
                SSLSessionContextImpl cache = (SSLSessionContextImpl)shc.sslContext
                        .engineGetServerSessionContext();

                // Consume a Session Ticket Extension if it exists
                SSLExtension[] ext = new SSLExtension[]{
                        SSLExtension.CH_SESSION_TICKET
                };
                clientHello.extensions.consumeOnLoad(shc, ext);

                SSLSessionImpl previous;
                // Use stateless session ticket if provided.
                if (shc.statelessResumption) {
                    previous = shc.resumingSession;
                } else {
                    previous = cache.get(clientHello.sessionId.getId());
                }

                boolean resumingSession =
                        (previous != null) && previous.isRejoinable();
                if (!resumingSession) {
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Can't resume, " +
                            "the existing session is not rejoinable");
                    }
                }
                // Validate the negotiated protocol version.
                if (resumingSession) {
                    ProtocolVersion sessionProtocol =
                            previous.getProtocolVersion();
                    if (sessionProtocol != shc.negotiatedProtocol) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                "Can't resume, not the same protocol version");
                        }
                    }
                }

                // Validate the required client authentication.
                if (resumingSession &&
                    (shc.sslConfig.clientAuthType == CLIENT_AUTH_REQUIRED)) {

                    try {
                        previous.getPeerPrincipal();
                    } catch (SSLPeerUnverifiedException e) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                "Can't resume, " +
                                "client authentication is required");
                        }
                    }
                }

                // Validate that the cached cipher suite.
                if (resumingSession) {
                    CipherSuite suite = previous.getSuite();
                    if ((!shc.isNegotiable(suite)) ||
                            (!clientHello.cipherSuites.contains(suite))) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                "Can't resume, " +
                                "the session cipher suite is absent");
                        }
                    }
                }

                // So far so good.  Note that the handshake extensions may reset
                // the resuming options later.
                shc.isResumption = resumingSession;
                shc.resumingSession = resumingSession ? previous : null;
            }

            HelloCookieManager hcm =
                shc.sslContext.getHelloCookieManager(ProtocolVersion.DTLS10);
            if (!shc.isResumption &&
                !hcm.isCookieValid(shc, clientHello, clientHello.cookie)) {
                //
                // Perform cookie exchange for DTLS handshaking if no cookie
                // or the cookie is invalid in the ClientHello message.
                //
                // update the responders
                shc.handshakeProducers.put(
                        SSLHandshake.HELLO_VERIFY_REQUEST.id,
                        SSLHandshake.HELLO_VERIFY_REQUEST);

                //
                // produce response handshake message
                //
                SSLHandshake.HELLO_VERIFY_REQUEST.produce(context, clientHello);

                return;
            }

            // cache the client random number for further using
            shc.clientHelloRandom = clientHello.clientRandom;

            // Check and launch ClientHello extensions.
            SSLExtension[] extTypes = shc.sslConfig.getEnabledExtensions(
                    SSLHandshake.CLIENT_HELLO);
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only need to ServerHello, which may add more responders later.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                    SSLHandshake.SERVER_HELLO);

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_STATUS,
                SSLHandshake.SERVER_KEY_EXCHANGE,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.SERVER_HELLO_DONE,

                // abbreviated handshake messages
                SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }

    /**
     * The "ClientHello" handshake message consumer for DTLS 1.3.
     */
    private static final
            class D13ClientHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private D13ClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
    
    static byte[] extractAndExpand(byte[] dh, byte[] kemctx) {
        String suiteId = "";
        int Nsecret = 32;
        byte[] eae_prk = labeledExtract("".getBytes(), "eae_prk".getBytes(), suiteId.getBytes(), dh);
        byte[] shared_secret = labeledExpand(eae_prk, "shared_secret".getBytes(),
                kemctx, suiteId, Nsecret);
        return shared_secret;
    }

    static byte[] labeledExtract(byte[] salt, byte[] label, byte[] suite_id, byte[] ikm) {
        byte[] labeled_ikm = concat("HPKE-v1".getBytes(), concat(suite_id, concat(label, ikm)));
        return extract(salt, labeled_ikm);
    }

    static byte[] labeledExpand(byte[] prk, byte[] label, byte[] info, String suite_id, int l) {
        String i2o = "00:32";
        byte[] labeled_info = concat(i2o.getBytes(), concat("HPKE-v1".getBytes(), concat(suite_id.getBytes(), concat(label, info))));
        return expand(prk, labeled_info, l);
    }

    static private byte[] extract(byte[] salt, byte[] inputKeyMaterial) {
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
    
    static final byte[] SUITEID = new byte[]{0x4b, 0x45, 0x4d, 0x0, 0x20}; //KEM0x0020
    
    static void deriveKeyPair(byte[] ikm) {
//        try {
            SomeWork.test9180A11();
//            HKDF hkdf = new HKDF("SHA256");
//            SecretKeySpec salt = null;
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//            baos.writeBytes("HPKE-v1".getBytes());
//            baos.writeBytes(SUITEID);
//            baos.writeBytes("dkp_prk".getBytes());
//            baos.writeBytes(ikm);
//            byte[] fullikm = baos.toByteArray();
//            SecretKeySpec inputKey = new SecretKeySpec(fullikm, "HKDF-IMK");
//            SecretKey extract = hkdf.extract(salt, inputKey, "dpk_prk");
//            
//            byte[] encoded = extract.getEncoded();
//            SSLLogger.info("intermediate key", encoded);
//            
//            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
//            baos2.writeBytes(new byte[]{0x0, 0x20});
//            baos2.writeBytes("HPKE-v1".getBytes());
//            baos2.writeBytes(SUITEID);
//            baos2.writeBytes("sk".getBytes());
//            byte[] ikm2 = baos2.toByteArray();
//            SecretKey expand = hkdf.expand(extract, ikm2, 32, "HKDF");
//SSLLogger.info("ikm2 = ", ikm2);
//            byte[] eencoded = expand.getEncoded();
//            SSLLogger.info("new key", eencoded);
//            
//                    NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
//        KeyFactory kf = KeyFactory.getInstance("XDH");
//        KeySpec privateSpec = new XECPrivateKeySpec(paramSpec,eencoded);
//        PrivateKey privateKey = kf.generatePrivate(privateSpec);
//            
//
//            PublicKey mypubkey = generatePublicKeyFromPrivate((XECPrivateKey)privateKey);
//            
////            
////            NamedGroup ng = NamedGroup.X25519;
////
////            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ng.algorithm);
////            kpg.initialize(ng.keAlgParamSpec, random);
////            kpg.generateKeyPair();
////            
////            byte[] dkp_prk = labeledExtract("".getBytes(), "".getBytes(), "dkp_prk".getBytes(), ikm);
////            byte[] sk = labeledExpand(dkp_prk, "sk".getBytes(), "".getBytes(), "", 32);
//            SSLLogger.info("deriveKeyPair results in ", mypubkey);
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
    }

    static protected int getIterationStartOffset() {
        return 1;
    }

    static byte[] concat(byte[] a, byte[] b) {
        int al = a.length; 
        int bl = b.length;
        byte[] c = new byte[al + bl];
        System.arraycopy(a, 0, c, 0, al);
        System.arraycopy(b, 0, c, al, bl);
        return c;        
    }
    
    public static  PublicKey generatePublicKeyFromPrivate(XECPrivateKey privateKey) throws GeneralSecurityException {
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
}

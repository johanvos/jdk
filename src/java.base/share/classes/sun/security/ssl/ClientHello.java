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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.text.MessageFormat;
import java.util.*;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import static sun.security.ssl.ClientAuthType.CLIENT_AUTH_REQUIRED;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SupportedVersionsExtension.CHSupportedVersionsSpec;

/**
 * Pack of the ClientHello handshake message.
 */
final class ClientHello {
    static final int OSSL_ECH_PADDING_TARGET = 256;
    static final int OSSL_ECH_PADDING_INCREMENT = 32;

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
        boolean inner;

        private static final byte[]  NULL_COMPRESSION = new byte[] {0};

        ClientHelloMessage(HandshakeContext handshakeContext,
                int clientVersion, SessionId sessionId,
                List<CipherSuite> cipherSuites, SecureRandom generator, boolean inner) {
            super(handshakeContext);
            this.inner = inner;
            Thread.dumpStack();
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
            this.extensions = new SSLExtensions(this, inner);

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
            Thread.dumpStack();
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
            hos.putInt8(0); // empty session id
            hos.putBytes16(getEncodedCipherSuites());
            hos.putBytes8(compressionMethod);
            this.extensions.send(hos);
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
        private HPKEContext hpkeContext;
        // Prevent instantiation of this class.
        private ClientHelloKickstartProducer() {
            // blank
        }

        KeyPair pruts() {
            try {
                String ecb = "c4:96:d5:4a:65:4b:3c:8c:da:75:ee:90:cf:26:cb:40:5a:61:e8:62:6a:10:4d:20:c9:b0:d9:a0:b8:f2:d5:59";
                byte[] eencoded = HexFormat.ofDelimiter(":").parseHex(ecb);
                NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
                KeyFactory kf = KeyFactory.getInstance("XDH");
                KeySpec privateSpec = new XECPrivateKeySpec(paramSpec, eencoded);

                PrivateKey myPrivateKey = kf.generatePrivate(privateSpec);
                PublicKey mypub = HPKEContext.generatePublicKeyFromPrivate((XECPrivateKey) myPrivateKey);
                SSLLogger.info("PRUTS PK = ", mypub);
                return new KeyPair(mypub, myPrivateKey);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                ex.printStackTrace();
            } catch (GeneralSecurityException ex) {
                ex.printStackTrace();
            }
            return null;
        }

        // Produce kickstart handshake message.
        @Override
        public byte[] produce(ConnectionContext context) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;
            String innerCh = System.getProperty("ech.hidden");
            if (innerCh != null) {
               // pruts();
                byte[] echConfigBytes = Files.readAllBytes(Path.of("/tmp/ech.conf"));
                this.echConfig = new ECHConfig(echConfigBytes);
                PublicKey peerPub = HPKEContext.convertEncodedPublicKey(echConfig.getPublicKey());
              //  KeyPair ephemeral = pruts(); //HPKEContext.deriveKeyPair(null);
                KeyPair ephemeral = HPKEContext.deriveKeyPair(null);
                SSLLogger.info("mypublickey", ephemeral.getPublic());
                this.hpkeContext = new HPKEContext(peerPub, ephemeral, this.echConfig.createInfo());
                hpkeContext.create();
                chc.hpkeContext = hpkeContext;
            }
            // clean up this producer
            chc.handshakeProducers.remove(SSLHandshake.CLIENT_HELLO.id);

            // session ID of the ClientHello message
            SessionId sessionId = new SessionId(new byte[0]);

            // a list of cipher suites sent by the client
            List<CipherSuite> ccipherSuites = chc.activeCipherSuites;
            List<CipherSuite> cipherSuites = new ArrayList<>();
            cipherSuites.addAll(ccipherSuites);
            cipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

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
                    chc.sslContext.getSecureRandom(), false);
            chc.initialClientHelloMsg = chm;
            
            // cache the client random number for further using
            chc.clientHelloRandom = chm.clientRandom;
            chc.clientHelloVersion = clientHelloVersion.id;

            // Produce extensions for ClientHello handshake message.
            SSLExtension[] extTypes = chc.sslConfig.getEnabledExtensions(
                    SSLHandshake.CLIENT_HELLO, chc.activeProtocols);
            chc.setEchConfig(echConfig);
            chm.extensions.produce(chc, extTypes);


            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ClientHello handshake message", chm);
            }

// ========= inner ECH
            ClientHelloMessage innerChm = new ClientHelloMessage(chc,
                    chc.clientHelloVersion, chm.sessionId, chm.cipherSuites,
                    chc.sslContext.getSecureRandom(), true);
            chc.setInnerEch(true);
            innerChm.extensions.produce(chc, extTypes);
            chc.setInnerEch(false);
            byte[] innerCH = innerChm.toByteArray();
            SSLLogger.info("inner CH", innerCH);
            System.err.println("Initially, inner CH = " + HexFormat.ofDelimiter(":").formatHex(innerCH));
            byte[] clear = innerChm.getEncodedByteArray();
            SSLLogger.info("Before padding, clear (" + clear.length + ") = ", clear);
            int clearLen = calculateClearLength(clear.length, echConfig.getMaxNameLength());
            byte[] newclear = new byte[clearLen];
            System.arraycopy(clear, 0, newclear, 0, clear.length);
            clear = newclear;
            SSLLogger.info("After padding, clear (" + clear.length + ") = ", clear);

            byte[] pkt = chm.toByteArray();
            SSLLogger.info("orignal packets (pkt)", pkt);
            int cipherlen = clearLen + 16; // not valid for all AEAD
            int echStart = pkt.length - 40;
            pkt = expandOuterCH(pkt, (byte) this.echConfig.getConfigId(), hpkeContext.getEphemeralPublicKeyBytes(), cipherlen);
            int echLength = pkt.length - echStart;
            System.err.println("ECHStart at " + echStart + " and length = " + echLength);
            SSLLogger.info("after expanding, pkt (" + pkt.length + ")", pkt);
            byte[] aad = new byte[pkt.length];

// set tmp extension so that we get correct size of extensions            
            byte[] tmpCH = new byte[pkt.length - echStart];
            System.arraycopy(pkt, echStart, tmpCH, 0, tmpCH.length);

            chm.extensions.updateExtension(SSLExtension.CH_ECH, tmpCH);
            pkt = chm.toByteArray();

            System.err.println("Pktlen = " + pkt.length + ", aadlen = " + aad.length + ", cipherlen = " + cipherlen);
            System.arraycopy(pkt, 0, aad, 0, aad.length);
            // pkt and aad now have correct extensions size and are equal
            // add first
            SSLLogger.info("Before cipher calc, aad = (" + aad.length + ")", aad);
            SSLLogger.info("Before cipher calc, clear = (" + clear.length + ")", clear);
//          byte[] AAD = HexFormat.ofDelimiter(":").parseHex(someAadString);
//          byte[] CLEAR = HexFormat.ofDelimiter(":").parseHex(someClearString);
            byte[] cipher = hpkeContext.seal(aad, clear);

            System.err.println("CIPHER = " + HexFormat.ofDelimiter(":").formatHex(cipher));
            // now modify pkt (clientouter) so that it has the cipher instead of zeroes
            // we do this by changing the ech extension and ask to recalculate (which is done when asking updateExtension and toByteArray)
            byte[] newCH = new byte[echLength];
            System.arraycopy(tmpCH, 0, newCH, 0, echLength);
            System.arraycopy(cipher, 0, newCH, echLength - cipherlen, cipherlen);
            chm.extensions.updateExtension(SSLExtension.CH_ECH, newCH);
            chc.innerClientHello = innerChm.toByteArray();
            SSLLogger.info("ClientHelloOuter = ", chm.toByteArray());

            // ===========
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
        
        private int calculateClearLength(int il, int mnl) {
            if (mnl > 0) {
                System.err.println("WARNING, ECHCONFIG DEFINED MAXNAMELENGTH! not supported!");
            }
            int innersnipadding = 0;
            int lengthWithSniPadding = innersnipadding + il;
            int lengthOfPadding = 31 - ((lengthWithSniPadding - 1) % 32);
            int lengthWithPadding = il + lengthOfPadding + innersnipadding;
            while (lengthWithPadding < OSSL_ECH_PADDING_TARGET) {
                lengthWithPadding += OSSL_ECH_PADDING_INCREMENT;
            }
            int clearLen = lengthWithPadding;
            SSLLogger.info("EAAE: Padding: mnl " + echConfig.getMaxNameLength() + ", lws: " + lengthWithSniPadding
                    + ",lop: " + lengthOfPadding + ", lwp: " + lengthWithPadding
                    + ", clear_len: " + clearLen + ", orig: " + il);

            return clearLen;
        }
        private byte[] expandOuterCH(byte[] src,byte cfgid, byte[] mypub, int cipherlen) {
            System.err.println("expand, src size = " + src.length+", cipherlen = "+cipherlen);
            byte[] answer = new byte[src.length + 2 + cipherlen];
            System.arraycopy(src, 0, answer, 0, src.length);
            int ef0dlength=1 + 4 + 1 + 2 + mypub.length+2+cipherlen;
            int lengthloc = src.length - 42;
            answer[lengthloc] = (byte)(ef0dlength/256);
            answer[lengthloc+1] = (byte) (ef0dlength%256);
            int cipherloc = src.length;
            answer[cipherloc] = (byte)(cipherlen/256);
            answer[cipherloc+1] = (byte)(cipherlen%256);
            System.err.println("expanded into size = "+answer.length);

            return answer; 
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
    static final String someAadString = 
            "03:03:38:cc:38:c6:fd:fe:ce:ca:f1:8d:e0:66:5d:85:"
    +"01:5a:6c:7e:84:b2:ac:e6:fe:02:30:d3:ee:8c:40:cc:"
    +"f2:70:20:9e:e8:ea:bf:fb:c8:a0:e6:3c:8a:12:be:75:"
    +"dd:f3:73:d7:9f:8b:d8:e9:82:a4:1b:42:6b:77:88:cd:"
    +"09:16:b1:00:08:13:02:13:03:13:01:00:ff:01:00:01:"
    +"f7:00:0b:00:04:03:00:01:02:00:0a:00:16:00:14:00:"
    +"1d:00:17:00:1e:00:19:00:18:01:00:01:01:01:02:01:"
    +"03:01:04:00:23:00:00:00:16:00:00:00:17:00:00:00:"
    +"0d:00:24:00:22:04:03:05:03:06:03:08:07:08:08:08:"
    +"1a:08:1b:08:1c:08:09:08:0a:08:0b:08:04:08:05:08:"
    +"06:04:01:05:01:06:01:00:2b:00:03:02:03:04:00:00:"
    +"00:12:00:10:00:00:0d:63:6f:76:65:72:2e:64:65:66:"
    +"6f:2e:69:65:00:10:00:12:00:10:05:6f:75:74:65:72:"
    +"06:70:75:62:6c:69:63:02:68:32:00:2d:00:02:01:01:"
    +"00:33:00:26:00:24:00:1d:00:20:e4:d4:36:00:3f:2a:"
    +"16:c4:cb:00:66:57:1f:95:5a:0d:a6:c7:44:3d:47:72:"
    +"07:e7:eb:46:70:02:e6:19:e2:60:fe:0d:01:3a:00:00:"
    +"01:00:01:50:00:20:59:bc:41:76:2a:4d:5f:d3:a3:0f:"
    +"4c:e7:0c:9e:94:c2:c3:f2:9b:9c:95:24:13:c3:97:70:"
    +"d2:d2:79:35:40:5d:01:10:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00";
    
    static final String someClearString = 
            "03:03:de:68:d1:55:5c:2a:84:4c:2d:dc:59:b5:aa:19:"
    +"dc:77:50:9a:4f:e2:bd:ce:cd:6c:26:df:c1:bf:9b:f5:"
    +"a7:db:00:00:08:13:02:13:03:13:01:00:ff:01:00:00:"
    +"74:fd:00:00:0f:0e:00:0b:00:0a:00:23:00:16:00:17:"
    +"00:0d:00:2b:00:00:00:0c:00:0a:00:00:07:64:65:66:"
    +"6f:2e:69:65:00:10:00:18:00:16:05:69:6e:6e:65:72:"
    +"06:73:65:63:72:65:74:08:68:74:74:70:2f:31:2e:31:"
    +"00:2d:00:02:01:01:00:33:00:26:00:24:00:1d:00:20:"
    +"d4:af:17:27:08:1a:7e:cf:e6:14:1e:b6:c9:4a:1a:3b:"
    +"cc:79:02:30:e2:6a:de:1a:c3:24:94:35:d0:79:4e:19:"
    +"fe:0d:00:01:01:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
    +"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
}

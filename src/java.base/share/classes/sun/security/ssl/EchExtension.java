package sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.StandardConstants;
import static sun.security.ssl.SSLExtension.CH_SERVER_NAME;
import static sun.security.ssl.SSLExtension.EE_SERVER_NAME;
import sun.security.ssl.SSLExtension.ExtensionConsumer;
import static sun.security.ssl.SSLExtension.SH_SERVER_NAME;
import sun.security.ssl.SSLExtension.SSLExtensionSpec;
import sun.security.ssl.SSLHandshake.HandshakeMessage;

final class EchExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHEchProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHEchConsumer();
    static final HandshakeAbsence chOnLoadAbsence = null;
    static final SSLStringizer chStringizer =
            new CHEchStringizer();

    static final HandshakeProducer eeNetworkProducer =
            new EEEchProducer();
    static final ExtensionConsumer eeOnLoadConsumer =
            new EEEchConsumer();

    /**
     * The "server_name" extension.
     *
     * See RFC 4366/6066 for the specification of the extension.
     */
    static final class CHEchsSpec implements SSLExtensionSpec {
        private CHEchsSpec() {
        }

        private CHEchsSpec(HandshakeContext hc,
                ByteBuffer buffer) throws IOException {
            if (buffer.remaining() < 2) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                    "Invalid server_name extension: insufficient data"));
            }
/*
            int sniLen = Record.getInt16(buffer);
            if ((sniLen == 0) || sniLen != buffer.remaining()) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                    "Invalid server_name extension: incomplete data"));
            }
*/

        }

        @Override
        public String toString() {
            return "<some ech client hello>";
        }

    }

    private static final class CHEchStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            try {
Thread.dumpStack();
                return (new CHEchsSpec(hc, buffer)).toString();
            } catch (IOException ioe) {
                // For debug logging only, so please swallow exceptions.
                return ioe.getMessage();
            }
        }
    }

    /**
     * Network data producer of a "server_name" extension in the
     * ClientHello handshake message.
     */
    private static final
            class CHEchProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CHEchProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
System.err.println("[ECH] CHECHPRODUCER");
Thread.dumpStack();
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(CH_SERVER_NAME)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                        "Ignore unavailable server_name extension");
                }
                return null;
            }

            // Produce the extension.
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.warning("IGNORE ECH EXTENSION FOR NOW!");
            }
            return new byte[]{1,2,3,4};
        }
    }

    /**
     * Network data consumer of a "server_name" extension in the
     * ClientHello handshake message.
     */
    private static final
            class CHEchConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHEchConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {
System.err.println("[ECH] CHECHConsumer");
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Is it a supported and enabled extension?
            if (!shc.sslConfig.isAvailable(CH_SERVER_NAME)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "Ignore unavailable extension: " + CH_SERVER_NAME.name);
                }
                return;     // ignore the extension
            }

            // Parse the extension.
            CHEchsSpec spec = new CHEchsSpec(shc, buffer);

            // Update the context.
            shc.handshakeExtensions.put(CH_SERVER_NAME, spec);

        }

    }

    /**
     * The "server_name" extension in the ServerHello handshake message.
     *
     * The "extension_data" field of this extension shall be empty.
     */
    static final class SHEchsSpec implements SSLExtensionSpec {
        static final SHEchsSpec DEFAULT = new SHEchsSpec();

        private SHEchsSpec() {
            // blank
        }

        private SHEchsSpec(HandshakeContext hc,
                ByteBuffer buffer) throws IOException {
            if (buffer.remaining() != 0) {
                throw hc.conContext.fatal(Alert.DECODE_ERROR,
                        new SSLProtocolException(
                    "Invalid ServerHello server_name extension: not empty"));
            }
        }

        @Override
        public String toString() {
            return "<empty extension_data field>";
        }
    }

    private static final class SHEchsStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            try {
                return (new SHEchsSpec(hc, buffer)).toString();
            } catch (IOException ioe) {
                // For debug logging only, so please swallow exceptions.
                return ioe.getMessage();
            }
        }
    }

    /**
     * Network data producer of a "ech" extension in the
     * EncryptedExtensions handshake message.
     */
    private static final
            class EEEchProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private EEEchProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
System.err.println("[ECH] EEECHProducer");
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // In response to "ech" extension request only
            return (new byte[0]);   // the empty extension_data
        }
    }

    /**
     * Network data consumer of a "server_name" extension in the
     * EncryptedExtensions handshake message.
     */
    private static final
            class EEEchConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private EEEchConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {
System.err.println("[ECH] EEECHconsumer");
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // In response to "server_name" extension request only
            CHEchsSpec spec = (CHEchsSpec)
                    chc.handshakeExtensions.get(CH_SERVER_NAME);
            if (spec == null) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                    "Unexpected EncryptedExtensions server_name extension");
            }

            // Parse the extension.
            if (buffer.remaining() != 0) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                    "Invalid EncryptedExtensions server_name extension");
            }

            // Update the context.
            chc.handshakeExtensions.put(
                    EE_SERVER_NAME, SHEchsSpec.DEFAULT);
            // The negotiated server name is unknown in client side. Just
            // use the first request name as the value is not actually used
            // in the current implementation.
        }
    }
}

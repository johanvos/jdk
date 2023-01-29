package sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import sun.security.ssl.ClientHello.ClientHelloMessage;
import sun.security.ssl.SSLExtension.ExtensionConsumer;
import sun.security.ssl.SSLHandshake.HandshakeMessage;
import sun.security.ssl.SSLExtension.SSLExtensionSpec;

public class EchExtension {
    static final HandshakeProducer chNetworkProducer =
            new CHEchProducer();
    static final ExtensionConsumer chOnLoadConsumer =
            new CHEchConsumer();
    static final HandshakeAbsence chOnLoadAbsence = null;
    static final EchStringizer echStringizer =
            new EchStringizer();

    /**
     * The "ech" extension.
     */
    static class EchSpec implements SSLExtensionSpec {

        private EchSpec(HandshakeContext hc,
                ByteBuffer m) throws IOException {
Thread.dumpStack();
        }

        @Override
        public String toString() {
            return "<some ech client hello>";
        }
    }

    private static final class EchStringizer implements SSLStringizer {
        @Override
        public String toString(HandshakeContext hc, ByteBuffer buffer) {
            return "ECH Extension, buffer = " + Arrays.toString(buffer.array());
        }
    }

    private static final
            class CHEchProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private CHEchProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            ClientHandshakeContext chc = (ClientHandshakeContext) context;

            // Is it a supported and enabled extension?
            if (!chc.sslConfig.isAvailable(SSLExtension.CH_ECH)) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                            "Ignore unavailable ech extension");
                }
                return null;
            }
            if (chc.echConfig == null) {
                SSLLogger.info("No ECHConfig found");
                return null;
            }
            ECHConfig echConfig = chc.getEchConfig();
            System.err.println("Need to produce ECHEXT, inner = "+chc.isInnerEch());
            byte[] answer = echConfig.produceExtension(chc.isInnerEch());
            if (!chc.innerEch) {
                ClientHelloMessage outer = chc.initialClientHelloMsg;
//                ClientHelloMessage innerChm = new ClientHelloMessage(chc,
//                        chc.clientHelloVersion, outer.sessionId, outer.cipherSuites,
//                        chc.sslContext.getSecureRandom(), true);
                HPKEContext hpkeContext = chc.hpkeContext;
                byte[] epb = hpkeContext.getEphemeralPublicKeyBytes();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(answer);
                baos.write(0);
                baos.write(0x20);
                baos.write(epb);
                answer = baos.toByteArray();
            }
            System.err.println("Will return ECHEXT, answer = "+Arrays.toString(answer));
            return answer;
        }
    }

    private static final
            class CHEchConsumer implements ExtensionConsumer {
        // Prevent instantiation of this class.
        private CHEchConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
            HandshakeMessage message, ByteBuffer buffer) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

Thread.dumpStack();
        }
    }

}

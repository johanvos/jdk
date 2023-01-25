package sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * EchConfig class
 * @author johan
 */
public class ECHConfig {
    
    static int DEFAULT_VERSION = 0xfe0d;
    static int CIPHER_LENGTH = 4;
    
    byte[] raw; // the original raw binary data. Everything else can be parsed from this.

    int rawLength; // including version etc
    int version;
    int length; // net length
    int configId;
    int kemId;
    byte[] publicKey;
    int[] cipher;
    HpkeSuite[] cipherSuite;
    HpkeSuite selectedSuite;
    String publicName;
    int maxNameLength;

    /**
     * Create ECH
     */
    public ECHConfig() {        
    }
    
    /**
     * constructor
     * @param binbuf raw data 
     */
    public ECHConfig(byte[] binbuf) {
        parse(binbuf);
    }
    
    /**
     * get raw data
     * @return raw data
     */
    public byte[] getRaw() {
        return this.raw;
    }

    /**
     * get max filename length
     * @return max
     */
    public int getMaxNameLength() {
        return this.maxNameLength;
    }

    /**
     * Get kem
     * @return kem 
     */
    public int getKemId() {
        return this.kemId;
    }

    /**
     * set version
     * @param v new version
     */
    public void setVersion(int v) {
        this.version = v;
    }
    
    /**
     * get version
     * @return the version
     */
    public int getVersion() {
        return this.version;
    }

    /**
     * set config id
     * @param b the id
     */
    public void setConfigId(byte b) {
        this.configId = b;
    }
    
    /**
     * get config id
     * @return the id
     */
    public int getConfigId() {
        return this.configId;
    }
    
    /**
     * get pk
     * @return the PK 
     */
    public byte[] getPublicKey() {
        return this.publicKey;
    }

    /**
     * Return the name we can use in the outer ClientHello.
     *
     * @return the public name
     */
    public String getPublicName() {
        return this.publicName;
    }

    private void parse(byte[] binbuf) {
        int ptr = 0;
        this.rawLength = readBytes(binbuf,ptr,2);
        System.err.println("rawlength = "+rawLength);
        ptr += 2;
        this.raw = new byte[rawLength];
        System.arraycopy(binbuf, 2, raw, 0, rawLength);
        this.version = readBytes(binbuf, ptr, 2);
        System.err.println("Version = "+version);
        ptr += 2;
        this.length = readBytes(binbuf, ptr, 2);
        ptr += 2;
        this.configId = readBytes(binbuf, ptr, 1);
        ptr++;
        this.kemId = readBytes(binbuf, ptr, 2);
        System.err.println("configId = "+configId);
        System.err.println("kemId = "+kemId);
        ptr += 2;
        int publen = readBytes(binbuf, ptr, 2);
        ptr += 2;
        this.publicKey = new byte[publen];
        System.arraycopy(binbuf, ptr, this.publicKey, 0, publen);
        System.err.println("PublicKey = "+Arrays.toString(this.publicKey));
        ptr +=publen;
        int cl = readBytes(binbuf, ptr, 2);
        ptr += 2;
        System.err.println("CL = "+cl+", ptr = "+ptr);
        int suiteCount = cl/CIPHER_LENGTH;
        cipher = new int[suiteCount];
        cipherSuite = new HpkeSuite[suiteCount];
        for (int i = 0; i < suiteCount; i++) {
            int val = readBytes(binbuf, ptr, 4);
            cipher[i] = val;
            System.err.println("Cipher = " + Integer.toHexString(val));
            HpkeSuite hs = new HpkeSuite(val/(1<<16), val%(1<<16) );
            cipherSuite[i] = hs;
            ptr += 4;
        }
        this.selectedSuite = cipherSuite[0];
        this.maxNameLength = readBytes(binbuf, ptr, 1);
        ptr++;
        int pubnamelen = readBytes(binbuf, ptr, 1);
        ptr++;
        System.err.println("Maxlen = " + maxNameLength+", pubnamelen = "+pubnamelen);
        byte[] pubname = new byte[pubnamelen];
        System.arraycopy(binbuf, ptr, pubname, 0, pubnamelen);
        this.publicName = new String(pubname);
        System.err.println("pubname = "+publicName);
        
    }
    
    int readBytes(byte[] src, int offset, int len) {
        int res = 0;
        for (int i = 0; i < len;i++) {
            res = res * 256 + (256+src[offset+i])%256;
        }
        return res;
    }
    
    /**
     * Create the bytes required for the encrypted_client_hello Extension
     * @return the bytes that need to be used in the extension. In case of 
     * an outer extension, the ephemeral public key (client generated) and
     * the payload need to be added separately (in EchExtension)
     * See https://datatracker.ietf.org/doc/draft-ietf-tls-esni/ section 5
     */
//     enum { outer(0), inner(1) } ECHClientHelloType;
//
//       struct {
//          ECHClientHelloType type;
//          select (ECHClientHello.type) {
//              case outer:
//                  HpkeSymmetricCipherSuite cipher_suite;
//                  uint8 config_id;
//                  opaque enc<0..2^16-1>;
//                  opaque payload<1..2^16-1>;
//              case inner:
//                  Empty;
//          };
//       } ECHClientHello;
   
    byte [] produceExtension(boolean inner) throws IOException {
        if (inner) {
            return new byte[]{0x1}; // code for inner = 0x1, rest is empty
        } else {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(0x0);
            baos.write(selectedSuite.toSerial());
            baos.write(this.configId);
            byte[] answer = baos.toByteArray();
            return answer;
        }
    }
    static final String OSSL_ECH_CONTEXT_STRING = "tls ech";

    /**
     * Create the info component required to create the HPKE context
     * @return 
     */
    public byte[] createInfo() {
        byte[] oecb = OSSL_ECH_CONTEXT_STRING.getBytes();
        byte[] info = new byte[oecb.length + 1 + getRaw().length];
        System.arraycopy(oecb, 0, info, 0, oecb.length);
        info[oecb.length] = 0;
        System.arraycopy(getRaw(), 0, info, oecb.length + 1, getRaw().length);
        return info;
    }

    @Override public String toString() {
        String v =  Integer.toHexString(version);
        return "ECHConfig version "+v
                + "\nInner length = "+length
                + "\nconfig_id = "+configId+" ("+Integer.toHexString(configId)+")"
                + "\npubname = "+this.publicName
                + "\npubkey = " + Arrays.toString(publicKey);
    }
    
    class HpkeSuite {
        int kdfId, aeadId;
        
        HpkeSuite(int k, int a) {
            System.err.println("Created Hpkesuite, kdfId = "+k+", aeaedid = "+a);
            this.kdfId = k;
            this.aeadId = a;
        }
        
        byte[] toSerial() {
            byte[] answer = new byte[4];
            answer[0] = (byte)(this.kdfId >> 8);
            answer[1] = (byte)(this.kdfId);
            answer[2] = (byte)(this.aeadId >> 8);
            answer[3] = (byte)(this.aeadId);
            return answer;
        }
    }
//    unsigned int public_name_len;
//    unsigned char *public_name;
//    unsigned int kem_id;
//    unsigned int pub_len;
//    unsigned char *pub;
//    unsigned int nsuites;
//    ech_ciphersuite_t *ciphersuites;
//    unsigned int maximum_name_length;
//    unsigned int nexts;
//    unsigned int *exttypes;
//    unsigned int *extlens;
//    unsigned char **exts;
//    size_t encoding_length; /* used for OSSL_ECH_INFO output */
//    unsigned char *encoding_start; /* used for OSSL_ECH_INFO output */
//    uint8_t config_id;

    
}

package javax.net.ssl;

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
     * Return the name we can use in the outer ClientHello
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
        for (int i = 0; i < suiteCount; i++) {
            cipher[i] = readBytes(binbuf, ptr, 4);
            System.err.println("Cipher = " + Integer.toHexString(cipher[i]));
            ptr += 4;
        }
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
    
    @Override public String toString() {
        String v =  Integer.toHexString(version);
        return "ECHConfig version "+v
                + "\nInner length = "+length
                + "\nconfig_id = "+configId+" ("+Integer.toHexString(configId)+")"
                + "\npubname = "+this.publicName
                + "\npubkey = " + Arrays.toString(publicKey);
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

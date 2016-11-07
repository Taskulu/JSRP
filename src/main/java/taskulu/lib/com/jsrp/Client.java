package taskulu.lib.com.jsrp;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import taskulu.lib.com.jsrp.objects.Verifier;

/**
 * SRP Client
 * Use 4096 prime as default
 * Compatibility with <a href="https://github.com/alax/jsrp">jsrp</a> and <a href="https://github.com/grempe/sirp">sirp</a>
 */

public class Client {

    private byte[] I;
    private byte[] P;
    private byte[] IU;
    private byte[] PU;
    private Configuration mConfig;
    private SRP mSRP;

    /**
     * Provide client with 4096 prime
     *
     * @param identifier
     * identifier(I) that use for SRP formula
     *
     * @param password
     * password(P) that use for SRP formula
     *
     * @return void
     * Use the {@link #setupClient(String, String, Configuration)} method to setup SRP
     */
    public Client(String identifier,String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        setupClient(identifier,password,new Configuration());
    }


    /**
     * Provide client with custom configuration
     *
     * @param identifier
     * identifier(I) that use for SRP formula
     *
     * @param password
     * password(P) that use for SRP formula
     *
     * @param config
     * Configuration that tell to use which prime, MessageDigest algorithm and g number according to SRP formula
     *
     * @return void
     * Use the {@link #setupClient(String, String, Configuration)} method to setup SRP
     */
    public Client(String identifier,String password,Configuration config) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        setupClient(identifier,password,config);
    }

    /**
     * Setup SRP
     *
     * @param identifier
     * identifier(I) that use for SRP formula
     *
     * @param password
     * password(P) that use for SRP formula
     *
     * @param config
     * Configuration that tell to use which prime, MessageDigest algorithm and g number according to SRP formula
     *
     * @return void
     * Use the {@link taskulu.lib.com.jsrp.SRP#SRP(String, String, BigInteger)}
     * and convert String identifier to type bytes(UTF-8 support)
     */
    private void setupClient(String identifier,String password,Configuration config) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        if(identifier == null || password == null)
            throw new NullPointerException("Username or Password can't be null");

        this.PU = (password.getBytes("UTF-8"));
        this.IU = (identifier.getBytes("UTF-8"));

        this.P = (password.getBytes());
        this.I = (identifier.getBytes());

        if(config == null)
            throw new NullPointerException("Configuration file can't be null");

        this.mConfig = config;

        this.mSRP = new SRP(mConfig.getG(),mConfig.getMeesageDigest(),Parameters.getPrime(mConfig.getPrimeLength()));
    }


    /**
     * Generate salt and verifier
     *
     * @return {@link taskulu.lib.com.jsrp.objects.Verifier}
     * Call {@link taskulu.lib.com.jsrp.SRP#v(byte[], byte[], byte[])}
     */
    public Verifier createVerifier(){

        BigInteger saltT = SRP.generateRandomSalt(256);
        byte[] salt = Transform.bigIntToArrayByte(saltT);

        return mSRP.v(IU,PU,salt);
    }


    /**
     * get A from SRP
     *
     * @return String
     * Call {@link taskulu.lib.com.jsrp.SRP#A(BigInteger)}
     */
    public String getPublicKey() {
        return this.mSRP.getA().toString(16);
    }


    /**
     * genrate M1 from SRP
     *
     * @param B
     * B from Server
     *
     * @param salt
     * salt from Server
     *
     * @return String
     * Call {@link taskulu.lib.com.jsrp.SRP#u(BigInteger, BigInteger)}
     * Call {@link taskulu.lib.com.jsrp.SRP#x(byte[], byte[], byte[])}
     * Call {@link taskulu.lib.com.jsrp.SRP#clientS(BigInteger, BigInteger, BigInteger, BigInteger)}
     * Call {@link taskulu.lib.com.jsrp.SRP#K(byte[])}
     * Call {@link taskulu.lib.com.jsrp.SRP#M1(byte[], byte[], byte[])}
     */
    public String getProof(String B, String salt)  {

        byte[] saltB = Transform.bigIntToArrayByte(new BigInteger(salt,16));

        String u = mSRP.u(Hex.decodeToByteArray(this.mSRP.getA().toString(16)),Hex.decodeToByteArray(B));

        BigInteger x = mSRP.x(I,P,saltB);

        byte[] sBuf = mSRP.clientS(new BigInteger((B),16),mSRP.getaInt(),new BigInteger(u,16),x);

        byte[] KBuf = mSRP.K(sBuf);

        byte[] m1 = mSRP.M1(Hex.decodeToByteArray(this.mSRP.getA().toString(16)),Hex.decodeToByteArray(B),KBuf);

        return Hex.encode(m1);

    }
}

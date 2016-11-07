package taskulu.lib.com.jsrp;

import android.util.Log;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import taskulu.lib.com.jsrp.objects.Verifier;

/**
 * SRP utility.
 *
 * Right now support all client side functions
 *
 * @// TODO: Add server side function to support all SRP usage
 *
 */

public class SRP {

    private BigInteger mG;
    private MessageDigest mHash;
    private BigInteger mPrime;
    private BigInteger aInt;
    private BigInteger ABuf;

    public SRP(String g, String meesageDigest, BigInteger prime) throws NoSuchAlgorithmException{
        this.mG = new BigInteger(g);
        this.mHash = MessageDigest.getInstance(meesageDigest);
        this.mPrime = prime;
        this.aInt = this.a();
        this.ABuf = this.A(aInt);
    }


    /**
     * Generate random 256 salt
     *
     * @return The resulting BigInteger
     */
    private BigInteger a(){
        return generateRandomSalt(256);
    }


    /**
     * Generate A from salt 'pow(g, a, N)'
     *
     * @param maInt
     *
     * @return The resulting BigInteger
     */
    public BigInteger A(BigInteger maInt){
        return mG.modPow(maInt,mPrime);
    }


    /**
     * Check if B is valid
     *
     * @param B The BigInteger from server
     *
     * @return Resulting that is valid
     */
    public Boolean isZeroWhenModN(BigInteger B) {
        return true;
    }


    /**
     * Verifier generator 'v = pow(g, x, N)'
     *
     * @param I bytes[] from identifier
     *
     * @param P bytes[] from password
     *
     * @param salt bytes[] from salt
     *
     * @return {@link taskulu.lib.com.jsrp.objects.Verifier}
     */
    public Verifier v(byte[] I,byte[] P,byte[] salt) {
        Verifier verifier = new Verifier();

        this.mHash.reset();
        this.mHash.update(I);
        this.mHash.update(":".getBytes(Charset.forName("UTF-8")));
        this.mHash.update(P);

        byte[] tempHash = mHash.digest();

        mHash.reset();

        mHash.update(salt);
        mHash.update(tempHash);

        BigInteger hashResult = new BigInteger(mHash.digest());

        BigInteger verifierResult = mG.modPow(hashResult,mPrime);

        String verifierString = verifierResult.toString(16);
        if(verifierString.length()%2 == 1)
            verifierString = "0" + verifierResult.toString(16);

        verifier.setVerifier(verifierString);
        verifier.setSalt(new BigInteger(salt).toString(16));

        return verifier;
    }

    public BigInteger getA() {
        return ABuf;
    }

    public BigInteger getaInt() {
        return aInt;
    }


    /**
     * Generate u 'H(A, B)'
     *
     * @param aInt A from client
     *
     * @param bInt B from server
     *
     * @return Resulting that is BigInteger
     */
    public BigInteger u(BigInteger aInt, BigInteger bInt) throws Exception {
        if(isZeroWhenModN(bInt)){
            mHash.update(Transform.bigIntToArrayByte(aInt));
            mHash.update(Transform.bigIntToArrayByte(bInt));
            byte[] result = mHash.digest();
            return new BigInteger(result);
        }
        else
            throw new Exception("Invalid B value, abort");
    }

    public String u(byte[] aInt, byte[] bInt) {
            mHash.update(aInt);
            mHash.update(bInt);
            byte[] result = mHash.digest();
            return Hex.encode(result);
    }


    /**
     * Generate x 'H(s, I, p)'
     *
     * @param I bytes[] from identifier
     *
     * @param P bytes[] from password
     *
     * @param salt bytes[] from salt
     *
     * @return Resulting that is BigInteger
     */
    public BigInteger x(byte[] I, byte[] P, byte[] salt) {

        this.mHash.reset();
        this.mHash.update(I);
        this.mHash.update(":".getBytes(Charset.forName("UTF-8")));
        this.mHash.update(P);

        byte[] tempHash = mHash.digest();

        mHash.reset();

        mHash.update((salt));
        mHash.update(tempHash);

        return new BigInteger(1,mHash.digest());
    }


    /**
     * Generate k 'H(N, g)'
     *
     * Use mG and mPrime from constructor
     *
     * @return Resulting that is BigInteger
     */
    public BigInteger k() {

        mHash.reset();
        mHash.update(Transform.transformToN(mPrime,mPrime.toString(16).length()));
        mHash.update(Transform.transformToN(mG,mPrime.toString(16).length()));

        return new BigInteger(mHash.digest());
    }


    /**
     * Generate client secret 'pow(B - k * pow(g, x, N), a + u * x, N)'
     *
     * @param bInt bytes[] from B
     *
     * @param aInt bytes[] from A
     *
     * @param u bytes[] from {@link #u(BigInteger, BigInteger)}
     *
     * @param x bytes[] from {@link #x(byte[], byte[], byte[])}
     *
     * @return Resulting that is byte[]
     */
    public byte[] clientS(BigInteger bInt, BigInteger aInt, BigInteger u, BigInteger x) {
        BigInteger result = bInt.subtract(this.k().multiply(mG.modPow(x,mPrime))).modPow(aInt.add(u.multiply(x)),mPrime);
        return (Transform.transformToN(result,mPrime.toString(16).length()));

    }


    /**
     * Generate K 'H(client_secret)'
     *
     * @param sBuf bytes[] from B
     *
     * @return Resulting that is byte[]
     */
    public byte[] K(byte[] sBuf) {
        mHash.reset();
        mHash.update(sBuf);
        return mHash.digest();
    }


    /**
     * Generate K 'H(client_secret)'
     *
     * @param a bytes[] from A
     *
     * @param b bytes[] from B
     *
     * @param K from {@link #k()}
     *
     * @return Resulting that is byte[]
     */
    public byte[] M1(byte[] a, byte[] b, byte[] k) {
        mHash.reset();
        mHash.update(a);
        mHash.update(b);
        mHash.update(k);
        return mHash.digest();
    }

    /**
     * Static method that generate random salt
     *
     * @param numBytes bytes number that we want
     *
     * @return Resulting salt
     */
    public static BigInteger generateRandomSalt(final int numBytes) {
        BigInteger temp = new BigInteger(numBytes,new SecureRandom());
        return temp;
    }

    @Override
    public String toString() {
        return "Using: " + mHash.getAlgorithm() + ", Prime length is" + mPrime.toString(16).length() + ", g is" + mG.toString(16);
    }
}

package taskulu.lib.com.jsrp;

/**
 * Configuration
 * @// TODO: Add other Primes and Digest
 */

class Configuration {

    public String getMeesageDigest() {
        return meesageDigest;
    }

    public void setMeesageDigest(String meesageDigest) {
        this.meesageDigest = meesageDigest;
    }

    static class PRIME_LENGTH {
        final static int N_4096 = 4096;
    }

    static class MESSAGE_DIGEST {
        final static String SHA_256 = "SHA-256";
    }

    private int primeLength = PRIME_LENGTH.N_4096;
    private String g = "05";
    private String meesageDigest = MESSAGE_DIGEST.SHA_256;

    public int getPrimeLength() {
        return primeLength;
    }

    public void setPrimeLength(int primeLength) {
        this.primeLength = primeLength;
    }

    public String getG() {
        return g;
    }

    public void setG(String g) {
        this.g = g;
    }
}

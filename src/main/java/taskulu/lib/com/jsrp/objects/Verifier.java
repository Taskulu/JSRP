package taskulu.lib.com.jsrp.objects;

/**
 * Verifier Object
 */

public class Verifier {
    private String salt;
    private String verifier;

    public String getVerifier() {
        return verifier;
    }

    public void setVerifier(String verifier) {
        this.verifier = verifier;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}

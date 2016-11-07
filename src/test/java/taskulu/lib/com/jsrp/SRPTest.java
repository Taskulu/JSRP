package taskulu.lib.com.jsrp;

/**
 * //@ todo:Write simple Integration test with Server/Client
 */
public class SRPTest {

    Client mClient;
    String identifier = "username";
    String password = "password";

    //@Before
    public void setUp() throws Exception {
        mClient = new Client(identifier,password);
    }
}
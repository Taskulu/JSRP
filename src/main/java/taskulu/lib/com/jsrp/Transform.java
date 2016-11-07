package taskulu.lib.com.jsrp;
import java.math.BigInteger;

/**
 * Transform class form (Javascript srp)
 */

public class Transform {

    /**
     * Map number in Array bytes with fix length
     * @param number
     * @param length
     * @return transform bytes
     */
    public static byte[] transformToN(BigInteger number,int length){
        String params = number.toString(16);
        int padding = params.length();
        String repeated = new String(new char[length]).replace("\0", "0");
        String g = repeated.substring(0,length-padding) + params.substring(0,padding);
        return Hex.decodeToByteArray(g);
    }

    /**
     * @param number
     * @return converted BigInt to bytes[]
     */
    public static byte[] bigIntToArrayByte(BigInteger number){
        String temp = number.toString(16);
        return Hex.decodeToByteArray(temp);
    }
}

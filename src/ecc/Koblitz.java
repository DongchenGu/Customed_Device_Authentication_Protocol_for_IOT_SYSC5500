package ecc;

import java.math.BigInteger;
import java.math.BigDecimal;
import java.math.MathContext;
import java.util.Arrays;

public class Koblitz {
    public static void main(String args[]) {
        BigInteger p = new BigInteger("6277101735386680763835789423207666416083908700390324961279", 10);
        BigInteger a = new BigInteger("0", 10);
        BigInteger b = new BigInteger("-4", 10);

        char message = 'k';

        BigInteger[] encoded_message = koblitz_encoding(message, a, b, p);

        System.out.println(Arrays.toString(encoded_message));

        char decoded_message = koblitz_decoding(encoded_message[0]);

        System.out.println(decoded_message);

    }

    public static BigInteger[] koblitz_encoding(char m, BigInteger a, BigInteger b, BigInteger p){

        int m_ascii_d = Integer.valueOf(m);
        String m_acsii_b = Integer.toBinaryString(m_ascii_d);

        String x_b = m_acsii_b;
        String counter_b = "";
        for (int i = 0; i < 183; i++){ // 183 = 192-8-1
            x_b = x_b + "0";
            counter_b += "1";
        }

        BigInteger x_d = new BigInteger(x_b, 2);
        BigInteger counter_d = new BigInteger(counter_b, 2);

        BigInteger y_square;

        BigInteger[] encoded = new BigInteger[2];

        while(!counter_d.equals(BigInteger.ZERO)){

            y_square = x_d.pow(3).add(x_d.multiply(a)).add(b).mod(p);

            if (isPerfectSquare(y_square)) {
                MathContext m_context = new MathContext(31);
                BigDecimal y2 = new BigDecimal(y_square);
                y2 = y2.sqrt(m_context);
                BigInteger sqrt = y2.toBigInteger();
                encoded[0] = x_d;
                encoded[1] = sqrt;
                return encoded;
            } else {
                x_d = x_d.add(BigInteger.ONE);
            }
            counter_d = counter_d.subtract(BigInteger.ONE);
        }
        encoded[0] = BigInteger.ZERO;
        encoded[1] = BigInteger.ZERO;
        return encoded;
    }

    public static char koblitz_decoding(BigInteger x){

        String x_b = x.toString(2);
        int length = x_b.length();
        length = length - 183;

        String m_b = x_b.substring(0, length);
        int m_ascii_d = Integer.valueOf(m_b, 2);
        char m = (char)m_ascii_d;

        return m;
    }

    public static boolean isPerfectSquare(BigInteger num) {
        if (num.equals(BigInteger.ZERO) || num.equals(BigInteger.ONE)){
            return true;
        }
        BigInteger low = BigInteger.ONE;
        BigInteger high = num;
        BigInteger mid;
        BigInteger squre;
        while (low.compareTo(high) == -1 || low.compareTo(high) == 0){
            mid = low.add(high).divide(BigInteger.TWO);

            squre = mid.pow(2);

            if (squre.equals(num)){
                return true;

            } else if (squre.compareTo(num) == -1){
                low = mid.add(BigInteger.ONE);
            } else {
                high = mid.subtract(BigInteger.ONE);
            }
        }
        return false;
    }
}
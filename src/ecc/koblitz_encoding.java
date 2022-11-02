public class Test {
    public static void main(String args[]){

        //int inverse = get_inverse(11, 4);
        //System.out.println(inverse);

        int p = 65537;
        int a = 4;
        int b = 20;

        char message = 'n';

        int encoded_message = koblitz_encoding(message, a, b, p);

        System.out.println(encoded_message);

        char decoded_message = koblitz_decoding(encoded_message);

        System.out.println(decoded_message);

    }

    public static int[] extended_euclidean(int p, int b){
        int r0, r1, q;
        int s0, s1, t0, t1;
        int [] arr = new int[2];
        int temp;

        r0 = p;
        r1 = b;
        s0 = 1;
        s1 = 0;
        t0 = 0;
        t1 = 1;

        while(r1 != 0){
            q = r0 / r1;
            temp = r0 - q * r1;
            r0 = r1;
            r1 = temp;

            temp = s0 - q * s1;
            s0 = s1;
            s1 = temp;

            temp = t0 - q * t1;
            t0 = t1;
            t1 = temp;
        }

        arr[0] = s0;
        arr[1] = t0;

        return arr;

    }

    public static int get_inverse(int p, int b){
        int t;
        int[] arr;

        arr = extended_euclidean(p, b);
        t = arr[1];
        if(t < 0){
            while(t < 0){
                t = t + p;
            }
        }
        return t;
    }

    public static int koblitz_encoding(char m, int a, int b, int p){

        int m_ascii_d = Integer.valueOf(m);
        String m_acsii_b = Integer.toBinaryString(m_ascii_d);
        String x_b = m_acsii_b + "00000000";
        double x_d = Integer.valueOf(x_b, 2);

        double sqrt_root;
        double y;
        int counter = 0;

        while(counter < 256){

            y = Math.pow(x_d, 3) + a * x_d + b;
            y = y % p;
            sqrt_root = Math.sqrt(y);
            if(sqrt_root % 1 == 0){
                return (int)x_d;
            } else {
                x_d = x_d + 1;
            }
        }
        return 0;
    }

    public static char koblitz_decoding(int x){

        String x_b = Integer.toBinaryString(x);
        int length = x_b.length();
        length = length - 8;

        String m_b = x_b.substring(0, length);
        int m_ascii_d = Integer.valueOf(m_b, 2);
        char m = (char)m_ascii_d;

        return m;
    }

}

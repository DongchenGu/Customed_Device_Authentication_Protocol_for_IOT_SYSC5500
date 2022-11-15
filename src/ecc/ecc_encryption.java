package ecc;

public class ecc_encryption {
    public static void main(String args[]){
        int p = 29;
        int a = 4;
        int b = 20;
        int Gx= 13;
        int Gy= 23;
        int Pr = 25;
        int Pu_x, Pu_y;
        int [] arr;
        int n;

        n = get_Gs_rank(Gx, Gy, p, a);

        System.out.println("G's rank is " + n);

        arr = multiplier(Gx, Gy, Pr,a, p);
        Pu_x = arr[0];
        Pu_y = arr[1];

        System.out.println("Public key: " + Pu_x + " " + Pu_y);

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


    public static int[] get_sum(int Px, int Py, int Qx, int Qy, int a, int p){
        int k;
        int i_d;
        int numerator;
        int denominator;
        int[] sum = new int[2];

        if(Px == Qx && Py == Qy){
            numerator = 3 * Px * Px + a;
            denominator = 2 * Py;
            i_d = get_inverse(p, denominator);
            k = (numerator * i_d) % p;
        } else {
            numerator = Qy - Py;
            while (numerator < 0){
                numerator = numerator + p;
            }
            denominator = Qx - Px;
            while (denominator < 0){
                denominator = denominator + p;
            }
            i_d = get_inverse(p, denominator);
            k = (numerator * i_d) % p;
        }

        sum[0] = (k * k - Px - Qx);
        if(sum[0] < 0){
            while (sum[0] < 0){
                sum[0] = sum[0] + p;
            }
        } else {
            sum[0] = sum[0] % p;
        }

        sum[1] = (k * (Px - sum[0]) - Py);
        if(sum[1] < 0){
            while (sum[1] < 0){
                sum[1] = sum[1] + p;
            }
        } else {
            sum[1] = sum[1] % p;
        }

        return sum;
    }

    public static int get_Gs_rank(int Gx, int Gy, int p, int a){
        int n = 1;
        int[] sum = new int[2];
        int minus_Gx = Gx;
        int minus_Gy = p - Gy;

        sum[0] = Gx;
        sum[1] = Gy;

        while(true){
            n++;
            sum = get_sum(Gx, Gy, sum[0], sum[1], a, p);
            if(sum[0] == minus_Gx && sum[1] == minus_Gy){
                n = n + 1;
                return n;
            } else if(n >= 100){
                System.out.println("G's rank is infinite");
                return 0;
            }
        }
    }

    public static int[] multiplier(int Px, int Py, int m, int a, int p){
        int[] sum = new int[2];
        int counter = 1;

        sum[0] = Px;
        sum[1] = Py;

        while(counter < m){
            sum = get_sum(Px, Py, sum[0], sum[1], a, p);
            counter ++;
        }
        return sum;

    }
}

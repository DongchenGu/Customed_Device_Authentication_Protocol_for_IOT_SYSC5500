package KeyedHash;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class KeyedHashGenerator {


    //小端方式写入数据，使得数据在内存中看起来是规律的
    private static final int INIT_A = 0x67452301;
    private static final int INIT_B = (int)0xEFCDAB89L;
    private static final int INIT_C = (int)0x98BADCFEL;
    private static final int INIT_D = 0x10325476;

    //这个数组对应的是上文中循环左移的s位
    private static final int[] SHIFT_AMTS = {
            7, 12, 17, 22,
            5,  9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
    };

    //对应上文中生成的T数组
    private static final int[] TABLE_T = new int[64];
    static
    {
        for (int i = 0; i < 64; i++)
            TABLE_T[i] = (int)(long)((1L << 32) * Math.abs(Math.sin(i + 1)));
    }

    public static byte[] computeMD5(byte[] message)
    {
        int messageLenBytes = message.length;
        /*
         *+8byte就是+64位，将结果右移6位也就是除以64，因为每64byte对应512bits，即一块。
         *此步求出填充后位串的总块数
         */
        int numBlocks = ((messageLenBytes + 8) >>> 6) + 1;
        int totalLen = numBlocks << 6; //填充后的总字节数
        //初始化填充的内容：1个1和若干个0
        byte[] paddingBytes = new byte[totalLen - messageLenBytes];
        paddingBytes[0] = (byte)0x80;

        //初始化填充的内容：最后64位
        long messageLenBits = (long)messageLenBytes << 3;
        for (int i = 0; i < 8; i++)
        {
            /*
             *每次将一个64位的long类型数据转为byte相当于截取其最低的8位
             *然后将这个数右移8位，下次再截取8位，也就是原数最低的16位
             */
            paddingBytes[paddingBytes.length - 8 + i] = (byte)messageLenBits;
            messageLenBits >>>= 8;
        }

        int a = INIT_A;
        int b = INIT_B;
        int c = INIT_C;
        int d = INIT_D;
        int[] buffer = new int[16]; //这里的buffer相当于前文的message数组
        for (int i = 0; i < numBlocks; i ++)
        {
            int index = i << 6;
            /*
             *将一个32位的int分为4个8位的byte
             *对于每个buffer[i]，执行循环中的四步将其初始化
             *每一步得到最终32位中的8位数据
             *最后用或运算将这些8位的中间结果连接起来
             */
            for (int j = 0; j < 64; j++, index++)
                buffer[j >>> 2] = ((int)((index < messageLenBytes) ? message[index] : paddingBytes[index - messageLenBytes]) << 24) | (buffer[j >>> 2] >>> 8);
            int originalA = a;
            int originalB = b;
            int originalC = c;
            int originalD = d;
            for (int j = 0; j < 64; j++)
            {
                //这个循环总共执行64次，每16次为一组（一个方框），div16用来选择不同方框中的函数FGHI
                int div16 = j >>> 4;
                int f = 0;
                int bufferIndex = j;
                switch (div16)
                {
                    //第一组不用选择bufferindex，按顺序读取buffer数组即可
                    case 0:
                        f = (b & c) | (~b & d);
                        break;

                    //第二组，bufferIndex用来选取数组中的特定元素
                    case 1:
                        f = (b & d) | (c & ~d);
                        bufferIndex = (bufferIndex * 5 + 1) & 0x0F;
                        break;

                    case 2:
                        f = b ^ c ^ d;
                        bufferIndex = (bufferIndex * 3 + 5) & 0x0F;
                        break;

                    case 3:
                        f = c ^ (b | ~d);
                        bufferIndex = (bufferIndex * 7) & 0x0F;
                        break;
                }
                /*
                 *循环左移，rotateLeft函数中的第二个参数用来指定左移的位数
                 *这里按照如下规则定义左移位数s
                 */
                int temp = b + Integer.rotateLeft(a + f + buffer[bufferIndex] + TABLE_T[j], SHIFT_AMTS[(div16 << 2) | (j & 3)]);
                //换位
                a = d;
                d = c;
                c = b;
                b = temp;
            }

            a += originalA;
            b += originalB;
            c += originalC;
            d += originalD;
        }

        byte[] md5 = new byte[16];
        int count = 0;
        for (int i = 0; i < 4; i++)
        {
            int n = (i == 0) ? a : ((i == 1) ? b : ((i == 2) ? c : d));
            for (int j = 0; j < 4; j++)
            {
                md5[count++] = (byte)n;
                n >>>= 8;
            }
        }
        return md5;
    }

    public static String toHexString(byte[] b)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++)
        {
            sb.append(String.format("%02X", b[i] & 0xFF));
        }
        return sb.toString();
    }

//    public static void main(String[] args)
//    {
//        String[] testStrings = { "", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890" };
//        for (String s : testStrings)
//            System.out.println("0x" + toHexString(computeMD5(s.getBytes())) + " <== \"" + s + "\"");
//        System.out.println(0x67452301);
//        return;
//    }

    public   String keyedHash(String mac,String serial, String time, String AESkey) throws UnsupportedEncodingException {
        String leftMost = mac+time;
        String rightMost = serial+time;
        byte[] LH = computeMD5(leftMost.getBytes(StandardCharsets.UTF_8));
        byte[] RH = computeMD5(rightMost.getBytes(StandardCharsets.UTF_8));

        byte[] preDH =new byte[16];
        byte[] DH3 = new byte[16];
        System.arraycopy(LH,0,preDH,0,8);
        System.arraycopy(RH,8,preDH,8,8);

        //测试是否拿到了preDH
        //System.out.println(new String(preDH));

        //拿preDH去做AES
        byte[] aesDH = new AESencrypt().AESencrypt(preDH, AESkey);

        //拿得到的加密结果做MD5得到最终的DH3
        DH3 = computeMD5(preDH);
        String DH3str = new String(DH3,"ISO-8859-1");
//        System.out.println(DH3str);
        return DH3str;
    }

//    public static void main(String[] args) throws UnsupportedEncodingException {
//        String mac = "E446B00F80D7";
//        String serial = "erjycrsd1343n";
//        long time = System.currentTimeMillis();
//        String key  = "urefbsdbfweufwet"; //一个英文字符占一个字节，必须有16个字节
//
//        String output = keyedHash(mac,serial,time,key);
//        System.out.println(output);
//    }
}

package ThreadSimulation;

import Decoder.BASE64Decoder;
import KeyedHash.KeyedHashGenerator;
import ECC2.ECCencrypt;
import java.util.Base64;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class TD {
    public static Base64.Decoder decoder = Base64.getDecoder();
    public static Base64.Encoder encoder = Base64.getEncoder();

    //将秘钥进行base64编码，然后再通过JSON传输
    public static String GetPublicKeyStr(ECPublicKey key){
        String KeyStr = new String(encoder.encodeToString(key.getEncoded()));
        return KeyStr;
    }
    public static String GetPrivateKeyStr(ECPrivateKey key){
        String KeyStr = new String(encoder.encodeToString(key.getEncoded()));
        return KeyStr;
    }
    //decode base64，拿到原来的类型
    public  static PublicKey strToPublicKey(String str) throws InvalidKeySpecException {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(
                    decoder.decode(str));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            //KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            //KeyFactory keyFactory = KeyFactory.getInstance("EC");
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return publicKey;
    }
    public static PrivateKey strToPrivateKey(String str){
        PrivateKey privateKey = null;
        try {
            byte[] keyBytes = (new BASE64Decoder()).decodeBuffer(str);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static void AuthenticateDevice(String key, int port){
            Socket socket = null;
            String mac;
            String serial;
            String time;
            String keyedHashTDH3=null;
            ECPublicKey MyPubKey = null;
            ECPrivateKey MyPriKey = null;
            //用来接收对方传来的公钥
            ECPublicKey OtherPubKey = null;

            ECCencrypt ECCModule = new ECCencrypt();

            try {
                //先生成自己的秘钥对
                ECCencrypt eCCencrypt = new ECCencrypt();
                KeyPair keyPair =eCCencrypt.getKeyPair();
                MyPubKey = (ECPublicKey) keyPair.getPublic();
                MyPriKey = (ECPrivateKey) keyPair.getPrivate();
            } catch (Exception e) {
                e.printStackTrace();
            }


            try{
                ServerSocket server = new ServerSocket(port);
                socket = server.accept();
                System.out.println("1");
                //由Socket对象得到输出流
                BufferedWriter bufferedWriter=new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),"UTF-8"));
                //由Socket对象得到输入流，并构造对应的BufferedReader对象
                BufferedReader bufferedReader=new BufferedReader(new InputStreamReader(socket.getInputStream(),"UTF-8"));


                //循环接收内容
                //返回ok表示认证成功
                //收到finished表示遇到错误直接断开
                //作为TD，监听客户端发来的认证请求
                while (true){
//                    System.out.println("3");
                    //然后要接收从客户端发过来的相应数据
                    //byte[] bytes = new byte[20];
                    char[] chars = new char[1024];
                    int len;
                    StringBuilder builder = new StringBuilder();
//                    while ((len=bufferedReader.read(chars)) != -1) {
//                        builder.append(new String(chars, 0, len));
//                    }
                    //使用socket长链接，手动判断结束符号
                    while ((len=bufferedReader.read(chars)) != -1 ) {
                        builder.append(new String(chars, 0, len));
                        //System.out.println(builder.toString());
                        if(builder.toString().endsWith("END")){
                            break;
                        }
                    }
                    String receive = builder.toString();
                    //将收到的字符串中的结束符号去掉，
                    receive = receive.substring(0,receive.length() - 3);
                    JSONObject FromClient = null;
                    String plainText = null;
                    //判断string是否是加密后的
                    try{
                        //不能获取的话说说明就是加密后的
                        FromClient = new JSONObject(receive);
                        System.out.println("message没有加密");
                    }
                    catch (JSONException e) {
                        //这里需要解密
                        System.out.println("TD收到加密请求，正在解密message。。。");
//                        //这里开始测试
//                        byte[] test  =ECCModule.encrypt("fsdfsdfsdf".getBytes(),MyPubKey);
//                        plainText = new String(ECCModule.decrypt(test,MyPriKey));

                        plainText = new String(ECCModule.decrypt(receive.getBytes(),MyPriKey));
                        System.out.println(plainText);
                        FromClient = new JSONObject(plainText);
                    }
                    //获得到认证请求中的tag标签
                    String tag =FromClient.getString("tag");


                    //分情况讨论，如果收到的是不是结束就继续进行认证过程
                    //接收到秘钥交换请求
                    if(tag.equals("Request_KeyExchange")){
                       String keyStr = FromClient.getString("publicKey");
                        System.out.println("TD已经接收到秘钥交换请求");
                        //将Str转换成PublicKey
                        OtherPubKey =(ECPublicKey)strToPublicKey(keyStr);
                        System.out.println(OtherPubKey.toString());

                        //然后需要将自己的publicKey传给Client
                        JSONObject JSON_ACK_KeyExchange=new JSONObject();
                        JSON_ACK_KeyExchange.put("tag", "ACK_KeyExchange");
                        JSON_ACK_KeyExchange.put("publicKey", GetPublicKeyStr(MyPubKey));
                        //将JSON发给client
                        bufferedWriter.write(JSON_ACK_KeyExchange.toString()+"END");
                        bufferedWriter.flush();
                        System.out.println("ACK_for_KeyExchange_SentOut");
                        continue;
                    }

                    if(tag.equals("Request_AuthenticationStart")){
                        System.out.println("TD收到Client认证请求");
                        //要接受从客户端发过来的Mac和serial的值
                        mac = FromClient.getString("mac");
                        serial = FromClient.getString("serial");

                        //生成时间戳,并转换成字符串
                        long currentTime = System.currentTimeMillis();
                        time = Long.toString(currentTime);


                        //生成TDH3的KeyedHash,并存下来留着后边比较用
                        keyedHashTDH3 = new KeyedHashGenerator().keyedHash(mac,serial,time,key);
                        //然后需要时间戳发送给客户
                        JSONObject JSON_time=new JSONObject();
                        JSON_time.put("tag", "ACK_mac&serial_timeProvided");
                        JSON_time.put("time", time);

                        //使用Client的publicKey进行加密
                        byte[] cipherText = ECCModule.encrypt(JSON_time.toString().getBytes(),OtherPubKey);
                        String cipherTextStr = cipherText.toString();
                        //将JSON发给client
                        bufferedWriter.write(cipherTextStr+"END");
                        bufferedWriter.flush();
                        System.out.println("ACK_TimeStamp_SentOut");

                    }else if(tag.equals("ERR_finished")){
                        System.out.println("TDH: Err! Request for the authentication is stopped");
                        bufferedWriter.close();
                        bufferedReader.close();
                        break;
                    }else if(tag.equals("DH3")){
                        System.out.println("TD收到Client发来的DH3");
                        //接收客户端发来的DH3的KeyedHash
                        String DH3 = FromClient.getString("DH3");
                        //判断和自己先前计算的值是否相等
                        if(DH3.equals(keyedHashTDH3)){
                            //认证成功，将ok返回给client
                            System.out.println("TDH:authentication pass!");
                            JSONObject JSON_result=new JSONObject();
                            JSON_result.put("tag", "ACK_OK");

                            //加密
                            byte[] cipherTest = ECCModule.encrypt(JSON_result.toString().getBytes(),OtherPubKey);
                            //发回客户端
                            bufferedWriter.write(new String(cipherTest)+"END");
                            bufferedWriter.flush();
                            bufferedWriter.close();
                            bufferedReader.close();
                            break;
                        }else{
                            //两者值不相等，认证失败ACK_NOT_MATCH
                            JSONObject JSON_result=new JSONObject();
                            JSON_result.put("tag", "ACK_NOT_MATCH");
                            //加密
                            byte[] cipherTest = ECCModule.encrypt(JSON_result.toString().getBytes(),OtherPubKey);
                            bufferedWriter.write(new String(cipherTest)+"END");
                            bufferedWriter.flush();
                            bufferedWriter.close();
                            bufferedReader.close();
                            break;
                        }

                    }

                }
                socket.close(); //关闭Socket

            }catch(Exception e) {
                System.out.println("Error"+e); //出错，则打印出错信息
            }
        }




    public static void main(String[] args) {
        String key = "urefbsdbfweufwet"; //一个英文字符占一个字节，必须有16个字节
        int port =4510;
        AuthenticateDevice(key,port);
    }
}

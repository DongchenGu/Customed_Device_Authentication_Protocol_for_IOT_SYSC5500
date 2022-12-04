package AuthenticationWithECCPresentation;

import Decoder.BASE64Decoder;
import ECC2.ECCencrypt;
import KeyedHash.KeyedHashGenerator;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


//client最先发起认证请求，TD用来验证
public class Client {
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
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (NoSuchAlgorithmException  e) {
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




    public static  void RequestAuthentication(String mac, String serial, String key,int  port){
        Socket socket = null;
        String time;
        String keyedHash;
        ECPublicKey MyPubKey = null;
        ECPrivateKey MyPriKey = null;
        //用来保存TD的公钥，这个公钥值是ECPublicKey key导出byte数组，然后再通过base64编码后得到的
        String OtherPubKey = null;
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
            //向本机的4700port发出客户请求
            socket=new Socket("127.0.0.1",port);

//            //由系统标准输入设备构造BufferedReader对象
//            BufferedReader sin=new BufferedReader(new InputStreamReader(System.in));

            //由Socket对象得到输出流
            BufferedWriter bufferedWriter=new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),"UTF-8"));
            //由Socket对象得到输入流，并构造对应的BufferedReader对象
            BufferedReader bufferedReader=new BufferedReader(new InputStreamReader(socket.getInputStream(),"UTF-8"));


            //客户端先发起请求，进行秘钥交换
            Map<String,String> KeyRequest = new HashMap<>();
            JSONObject JSONKeyRequest=new JSONObject();
            JSONKeyRequest.put("tag", "Request_KeyExchange");
//            System.out.println("客户端的公钥");
//            System.out.println(MyPubKey.hashCode());
            //把公钥转换成str发送出去
            String publicKeyStr = GetPublicKeyStr(MyPubKey);
            JSONKeyRequest.put("publicKey",publicKeyStr);
            //将JSON发给TD,手动加入结束符号，提供判断
            bufferedWriter.write(JSONKeyRequest.toString()+"END");
            bufferedWriter.flush();
            System.out.println("Client: KeyExchange Request sent out!");


            //循环接收内容
            //收到ok表示认证成功
            //收到finished表示遇到错误直接断开。
            while (true){
                //然后要接收从服务器发过来的相应数据
                char[] chars = new char[1024];
                int len;
                StringBuilder builder = new StringBuilder();
                while ((len=bufferedReader.read(chars)) != -1) {
                    builder.append(new String(chars, 0, len));
                    if(builder.toString().endsWith("END")){
                        break;
                    }
                }
                String receive = builder.toString();
                //将收到的字符串中的结束符号去掉，
                receive = receive.substring(0,receive.length() - 3);
                String plainText = null;
                JSONObject authenticationFromTD = null;

                //判断string是否是加密后的
                try{
                    //不能获取的话说说明就是加密后的
                    authenticationFromTD = new JSONObject(receive);
                    System.out.println("Client: receive new packet, message not encrypted");
                }
                catch (JSONException e) {
                    //这里需要解密
                    System.out.println("Client(ECC encrypted): receive ECC encrypted message，decrypt.....");
                    plainText = new String(ECCModule.decrypt(receive.getBytes("ISO-8859-1"),GetPrivateKeyStr(MyPriKey)));
//                    System.out.println(plainText);
                    authenticationFromTD = new JSONObject(plainText);
                }
                //获得到TD回复中的tag标签
                String tag =authenticationFromTD.getString("tag");



                //分情况讨论，如果收到的是不是结束就继续进行认证过程
                if(tag.equals("ACK_KeyExchange")){
                        String TDKeyStr = authenticationFromTD.getString("publicKey");
                        System.out.println("Client: TD-publicKey received");

                        //直接用base64编码后的公钥
                        OtherPubKey =TDKeyStr;
                    //System.out.println(OtherPubKey.toString());

                        //秘钥交换流程结束，开始发送认证请求
                        //客户端发起认证，需要将Mac和serial发给服务器端，
                        Map<String,String> request = new HashMap<>();
                        JSONObject JSONrequest=new JSONObject();
                        JSONrequest.put("tag", "Request_AuthenticationStart");
                        JSONrequest.put("mac", mac);
                        JSONrequest.put("serial", serial);
                        //使用TD 的publicKey进行ECC加密
                        byte[] cipherTxt =ECCModule.encrypt(JSONrequest.toString().getBytes("ISO-8859-1"),OtherPubKey);
                        //将JSON发给TD,手动加入结束符号，提供判断
                        bufferedWriter.write(new String(cipherTxt,"ISO-8859-1")+"END");
                        bufferedWriter.flush();
                        System.out.println("Client(ECC encrypted): Authentication Request sent out");
                        continue;
                }
                if(tag.equals("ACK_mac&serial_timeProvided")){
                    //要接受从TD传过来的time值
                    time = authenticationFromTD.getString("time");
                    System.out.println("Client(ECC encrypted): TimeStamp received "+time);
                    if(time!=null){
                        //重新计算KeyedHash
                        keyedHash = new KeyedHashGenerator().keyedHash(mac,serial,time,key);
                        System.out.println("Client(ECC encrypted): DH3 generated："+keyedHash);
                        //然后需要将计算出的keyedHash结果发给TD
                        JSONObject JSON_DH3_Back=new JSONObject();
                        JSON_DH3_Back.put("tag", "DH3");
                        JSON_DH3_Back.put("DH3", keyedHash);
                        //使用TD的publicKey加密
                        byte[] cipherTxt =ECCModule.encrypt(JSON_DH3_Back.toString().getBytes("ISO-8859-1"),OtherPubKey);

                        //将JSON发给TD
                        bufferedWriter.write(new String(cipherTxt,"ISO-8859-1")+"END");
                        bufferedWriter.flush();
                        System.out.println("Client(ECC encrypted): DH3 sent out");
                    }else{
                        System.out.println("Client(ECC encrypted): error! not a valid timestamp");
                        JSONObject ERR=new JSONObject();
                        ERR.put("tag", "ERR_finished");
                        //使用TD的publicKey加密
                        byte[] cipherTxt =ECCModule.encrypt(ERR.toString().getBytes("ISO-8859-1"),OtherPubKey);
                        bufferedWriter.write(new String(cipherTxt,"ISO-8859-1")+"END");
                        bufferedWriter.flush();
                        bufferedWriter.close();
                        bufferedReader.close();
                        break;
                    }
                }else if(tag.equals("ERR_finished")){
                    System.out.println("Client(ECC encrypted): Err! Server refuses to respond");
                    bufferedWriter.close();
                    bufferedReader.close();
                    break;
                }else if(tag.equals("ACK_OK")){
                    System.out.println("Client(ECC encrypted)：receive feedback");
                    System.out.println("Client(ECC encrypted): authentication pass!");
                    bufferedWriter.close();
                    bufferedReader.close();
                    break;
                }else if(tag.equals("ACK_NOT_MATCH")){
                    System.out.println("Client(ECC encrypted): authentication fail!");
                    bufferedWriter.close();
                    bufferedReader.close();
                    break;
                }

            }



//            //若从标准输入读入的字符串为 "bye"则停止循环
//            while(!readline.equals("bye")){
//                //将从系统标准输入读入的字符串输出到Server
//                os.println(readline);
//
//
//                //刷新输出流，使Server立即收到该字符串
//                os.flush();
//
//
//                //在系统标准输出上打印读入的字符串
//                System.out.println("Client:"+readline);
//                //从Server读入一字符串，并打印到标准输出上
//                System.out.println("Server:"+is.readLine());
//
//                readline=sin.readLine(); //从系统标准输入读入一字符串
//
//            } //继续循环


            socket.close(); //关闭Socket

        }catch(Exception e) {

            System.out.println("Error"+e); //出错，则打印出错信息

        }
    }




    public static void main(String[] args) {
        long startTime=System.currentTimeMillis();

        int port =4510;
        String mac = "E446B00F80D7";
        String serial = "erjycrsd1343n";
        String key = "urefbsdbfweufwet"; //一个英文字符占一个字节，必须有16个字节


        RequestAuthentication(mac,serial,key,port);

        long endTime = System.currentTimeMillis(); //获取结束时间

        System.out.println("Clinet time consumption： "+(endTime - startTime)+"ms");
    }
}

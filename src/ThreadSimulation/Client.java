package ThreadSimulation;

import Decoder.BASE64Decoder;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.net.Socket;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import  org.json.*;
import KeyedHash.KeyedHashGenerator;
import java.security.KeyPair;
import ECC2.ECCencrypt;

import java.io.IOException;
import java.security.*;
import java.security.spec.*;





//client最先发起认证请求，TD用来验证
public class Client {

    //将秘钥进行base64编码，然后再通过JSON传输
    public static String GetPublicKeyStr(ECPublicKey key){
        String KeyStr = new String(Base64.encodeBase64(key.getEncoded()));
        return KeyStr;
    }
    public static String GetPrivateKeyStr(ECPrivateKey key){
        String KeyStr = new String(Base64.encodeBase64(key.getEncoded()));
        return KeyStr;
    }
    //decode base64，拿到原来的类型
    public  static PublicKey strToPublicKey(String str){
        PublicKey publicKey = null;
        try {

            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(
                    new BASE64Decoder().decodeBuffer(str));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
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
        //用来接收对方传来的公钥
        ECPublicKey OtherPubKey = null;

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
            //把公钥转换成str发送出去
            String publicKeyStr = GetPublicKeyStr(MyPubKey);
            JSONKeyRequest.put("publicKey",publicKeyStr);
            //将JSON发给TD,手动加入结束符号，提供判断
            bufferedWriter.write(JSONKeyRequest.toString()+"END");
            bufferedWriter.flush();



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
                //获得到TD回复中的tag标签
                JSONObject authenticationFromTD = new JSONObject(receive);
                String tag =authenticationFromTD.getString("tag");

                //分情况讨论，如果收到的是不是结束就继续进行认证过程
                if(tag.equals("ACK_KeyExchange")){
                        String TDKeyStr = authenticationFromTD.getString("publicKey");
                        System.out.println("Client已经接收TD返回的publicKey");
                        //将Str转换成PublicKey
                        OtherPubKey =(ECPublicKey)strToPublicKey(TDKeyStr);

                        //秘钥交换流程结束，开始发送认证请求
                        //客户端发起认证，需要将Mac和serial发给服务器端，
                        Map<String,String> request = new HashMap<>();
                        JSONObject JSONrequest=new JSONObject();
                        JSONrequest.put("tag", "Request_AuthenticationStart");
                        JSONrequest.put("mac", mac);
                        JSONrequest.put("serial", serial);
                        //使用TD 的publicKey进行ECC加密
                        byte[] cipherTxt =new ECCencrypt().encrypt(JSONrequest.toString().getBytes(),OtherPubKey);
                        //将JSON发给TD,手动加入结束符号，提供判断
                        bufferedWriter.write(new String(cipherTxt)+"END");
                        bufferedWriter.flush();

                }
                if(tag.equals("ACK_mac&serial_timeProvided")){
                    //要接受从TD传过来的time值
                    time = authenticationFromTD.getString("time");
                    System.out.println("客户端已经或得到time值"+time);
                    if(time!=null){
                        //重新计算KeyedHash
                        keyedHash = new KeyedHashGenerator().keyedHash(mac,serial,time,key);
                        //然后需要将计算出的keyedHash结果发给TD
                        JSONObject JSON_DH3_Back=new JSONObject();
                        JSON_DH3_Back.put("tag", "DH3");
                        JSON_DH3_Back.put("DH3", keyedHash);
                        //将JSON发给TD
                        bufferedWriter.write(JSON_DH3_Back.toString()+"END");
                        bufferedWriter.flush();
                    }else{
                        System.out.println("ClientNode: error! not a valid timestamp");
                        JSONObject ERR=new JSONObject();
                        ERR.put("tag", "ERR_finished");
                        bufferedWriter.write(ERR.toString()+"END");
                        bufferedWriter.flush();
                        bufferedWriter.close();
                        bufferedReader.close();
                        break;
                    }
                }else if(tag.equals("ERR_finished")){
                    System.out.println("ClientNode: Err! Server refuses to respond");
                    bufferedWriter.close();
                    bufferedReader.close();
                    break;
                }else if(tag.equals("ACK_OK")){
                    System.out.println("ClientNode: authentication pass!");
                    bufferedWriter.close();
                    bufferedReader.close();
                    break;
                }else if(tag.equals("ACK_NOT_MATCH")){
                    System.out.println("ClientNode: authentication fail!");
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
        int port =4510;
        String mac = "E446B00F80D7";
        String serial = "erjycrsd1343n";
        String key = "urefbsdbfweufwet"; //一个英文字符占一个字节，必须有16个字节
        RequestAuthentication(mac,serial,key,port);
    }
}

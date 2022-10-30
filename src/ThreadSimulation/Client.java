package ThreadSimulation;

import java.io.*;
import java.net.Socket;
import java.rmi.MarshalledObject;
import java.util.HashMap;
import java.util.Map;
import  org.json.*;
import KeyedHash.KeyedHashGenerator;



//client最先发起认证请求，TD用来验证
public class Client {

    public static  void RequestAuthentication(String mac, String serial, String key,int  port){
        Socket socket = null;
        String time;
        String keyedHash;


        try{
            //向本机的4700port发出客户请求
            socket=new Socket("127.0.0.1",port);

//            //由系统标准输入设备构造BufferedReader对象
//            BufferedReader sin=new BufferedReader(new InputStreamReader(System.in));

            //由Socket对象得到输出流
            BufferedWriter bufferedWriter=new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),"UTF-8"));
            //由Socket对象得到输入流，并构造对应的BufferedReader对象
            BufferedReader bufferedReader=new BufferedReader(new InputStreamReader(socket.getInputStream(),"UTF-8"));




            //客户端发起认证，需要将Mac和serial发给服务器端，
            //这里需要加入加密环节，先忽略
            Map<String,String> request = new HashMap<>();
            JSONObject JSONrequest=new JSONObject();
            JSONrequest.put("tag", "Request_AuthenticationStart");
            JSONrequest.put("mac", mac);
            JSONrequest.put("serial", serial);
            //将JSON发给TD,手动加入结束符号，提供判断
            bufferedWriter.write(JSONrequest.toString()+"END");
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

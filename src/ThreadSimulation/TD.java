package ThreadSimulation;

import KeyedHash.KeyedHashGenerator;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class TD {



    public static void AuthenticateDevice(String key, int port){
            Socket socket = null;
            String mac;
            String serial;
            String time;
            String keyedHashTDH3=null;

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
                    System.out.println("3");
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
                    //System.out.println(receive);
                    //获得到认证请求中的tag标签
                    JSONObject FromClient = new JSONObject(receive);
                    String tag =FromClient.getString("tag");
                    //System.out.println(tag);

                    //分情况讨论，如果收到的是不是结束就继续进行认证过程
                    if(tag.equals("Request_AuthenticationStart")){
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
                        //将JSON发给client
                        bufferedWriter.write(JSON_time.toString()+"END");
                        bufferedWriter.flush();

                    }else if(tag.equals("ERR_finished")){
                        System.out.println("TDH: Err! Request for the authentication is stopped");
                        bufferedWriter.close();
                        bufferedReader.close();
                        break;
                    }else if(tag.equals("DH3")){
                        //接收客户端发来的DH3的KeyedHash
                        String DH3 = FromClient.getString("DH3");
                        //判断和自己先前计算的值是否相等
                        if(DH3.equals(keyedHashTDH3)){
                            //认证成功，将ok返回给client
                            System.out.println("TDH:authentication pass!");
                            JSONObject JSON_result=new JSONObject();
                            JSON_result.put("tag", "ACK_OK");
                            bufferedWriter.write(JSON_result.toString()+"END");
                            bufferedWriter.flush();
                            bufferedWriter.close();
                            bufferedReader.close();
                            break;
                        }else{
                            //两者值不相等，认证失败ACK_NOT_MATCH
                            JSONObject JSON_result=new JSONObject();
                            JSON_result.put("tag", "ACK_NOT_MATCH");
                            bufferedWriter.write(JSON_result.toString()+"END");
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

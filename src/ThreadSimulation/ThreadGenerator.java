package ThreadSimulation;

import java.io.*;
import java.net.Socket;

public class ThreadGenerator {

    //创建两个线程类，一个Client一个TD(target device)
    //client最先发起认证请求，TD用来验证
    public class Client implements Runnable{

        String mac = "E446B00F80D7";
        String serial = "erjycrsd1343n";
        @Override
        public void run() {
            Socket socket = null;
            try {
                String host = "127.0.0.1";
                int port = 8888;

                //创建套接字,套接字是传输层Tcp像应用层Http开的一个编程接口，开发人员主要是通过套接字对tcp进行编程
                socket = new Socket(host,8888);

                //向服务端发起一个请求，通过socket创建io输出流
                OutputStream outputStream = socket.getOutputStream();

                //通过io输出流创建数据输出流
                DataOutputStream dataOutputStream = new DataOutputStream(outputStream);

                //发起请求，这里直接传了一个hello过去
                dataOutputStream.writeUTF(mac,serial);

                //通过socket创建io输入流
                InputStream inputStream = socket.getInputStream();

                //通过io输入流创建数据输入流
                DataInputStream dataInputStream = new DataInputStream(inputStream);

                //接收服务端的响应
                String s = dataInputStream.readUTF();
                System.out.println("客户端接收到的数据：[ " + s + " ]");

                //关闭数据传输流
                dataOutputStream.close();
                dataInputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    public class TD implements Runnable{

        @Override
        public void run() {

        }


    }

    public static void main(String[] args) {

    }
}

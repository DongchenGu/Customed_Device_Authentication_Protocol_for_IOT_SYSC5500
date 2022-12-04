package AuthenticationWithECCPresentation;

import AuthenticationWithECCPresentation.Client;
import AuthenticationWithECCPresentation.TD;

public class AuthenticationProcess {
    public static void main(String[] args) {

        int port =4510;
        String client_mac = "E446B00F80D7";
        String client_serial = "erjycrsd1343n";
        String client_key = "urefbsdbfweufwet"; //一个英文字符占一个字节，必须有16个字节

        String TD_key = "urefbsdbfweufwet"; //一个英文字符占一个字节，必须有16个字节

        long startTime=System.currentTimeMillis();
        TD.AuthenticateDevice(TD_key,port);
        Client.RequestAuthentication(client_mac,client_serial,client_key,port);
        long endTime=System.currentTimeMillis(); //获取结束时间
        System.out.println("Time consumption： "+(endTime - startTime)+"ms");

    }

}

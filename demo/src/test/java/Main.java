import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class Main {
    public static String handleRequestBody(String request_body) {
        String result = null;
        try {
            String request_body_decode = URLDecoder.decode(request_body, "UTF-8");
            if (request_body_decode.contains("{\"")) {
                request_body = request_body_decode;
            }
            result = request_body;  // 假设处理成功后将处理后的结果返回
        } catch (UnsupportedEncodingException e) {
            System.err.println("不支持的编码格式：" + e.getMessage());
            // 比如返回一个默认值或者空字符串等作为错误时的返回结果
            result = "";  
        } catch (Exception e) {
            System.err.println("其他异常发生：" + e.getMessage());
            result = "";
        }
        return result;
    }

    public static void main(String[] args) {
        String testRequestBody = "data=%7B%22a%22%3A%22b%22%7D";
        String processedBody = handleRequestBody(testRequestBody);
        System.out.println(processedBody);
    }
}
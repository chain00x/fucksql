import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexDemo {
    public static void main(String[] args) {
        String input = "{\"productCode\":\"AD8909\",\"type\":1,\"thirdSession\":\"8wPtr4XBB0A8000001367968173\"}";
        String pattern = "\\d+"; // 匹配一个或多个数字

        // 创建Pattern对象
        Pattern regex = Pattern.compile(pattern);

        // 创建Matcher对象
        Matcher matcher = regex.matcher(input);

        // 查找匹配
        if (matcher.find()) {
            String match = matcher.group(); // 获取匹配到的字符串
            System.out.println("匹配到的结果: " + match);
        } else {
            System.out.println("未找到匹配项");
        }
    }
}
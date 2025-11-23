import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexDemo {
    public static void main(String[] args) {
        String input = "{\"id\":1}}";
        String pattern = "(\"|\\\\\")(\\S+?)(\"|\\\\\"):(\"|\\\\\")(?!\\{)(.*?)(\"|\\\\\")"; // 匹配一个或多个数字

        // 创建Pattern对象
        Pattern regex = Pattern.compile(pattern);

        // 创建Matcher对象
        Matcher matcher = regex.matcher(input);

        // 查找匹配
        while (matcher.find()) {
            System.out.println("匹配到的结果: " + matcher.group(4) + matcher.group(5));
            
        }
    }
}
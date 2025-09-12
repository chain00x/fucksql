import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {
    public static void main(String[] args) {
        String pattern = "(\"|\\\\\")(\\S+?)(\"|\\\\\")(:\\[?)(\\d+|null)";
        Pattern r = Pattern.compile(pattern);
        String data = "{\"a\":\"b\",\"c\":null}";
        Matcher m = r.matcher(data);
        while (m.find()) {
            // if(m.group(4).equals("")){
            //     System.out.println(m.group(3));
            // }
            System.out.println(m.group(5));
        }
    }
}
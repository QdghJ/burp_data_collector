import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Test {

    public static void main(String[] args) {
        String domain = "ff.ee.dd.aa.bb.cc";
        //String domain = "127.0.0.1";
        String reg = "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$";
        Matcher matcher = Pattern.compile(reg).matcher(domain);
        if (matcher.find()) {
            System.out.println("is ip");
            return;
        }


        String[] subs = domain.split("\\.");
        int len = subs.length;
        if (len == 2)
            return;

        for (int l = 0; l < len - 3; l++) {
            System.out.println(subs[l]);
        }
        for (int i = len - 3, j = 0; j <= i; j++) {
            StringBuilder stringBuilder = new StringBuilder();
            for (int k = j; k < i; k++) {
                stringBuilder.append(subs[k]);
                stringBuilder.append(".");
            }
            stringBuilder.append(subs[i]);
            System.out.println(stringBuilder.toString());
        }
    }
}

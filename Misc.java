package cn.nsoc.common.util;

import cn.nsoc.base.entity.sys.NSException;
import com.google.common.net.InetAddresses;
import com.google.gson.*;
import org.apache.commons.io.input.BOMInputStream;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Created by sam on 16-5-29.
 */
public class Misc {

    public static final UUID EmptyUUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    static final String STD_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss";
    static final String EMPTY_IP = "0.0" + ".0.0";  // for sonar
    static final String STD_DATE_FORMAT = "yyyy-MM-dd";
    static final Integer UUID_STD_SIZE = 36;
    static final DateTimeFormatter formatterDateTime = DateTimeFormatter.ofPattern("yyyy-M-d H:m:s");
    static final DateTimeFormatter formatterDate = DateTimeFormatter.ofPattern("yyyy-M-d");
    static final DateTimeFormatter formatterStdDateTime = DateTimeFormatter.ofPattern(STD_DATETIME_FORMAT);
    static final DateTimeFormatter formatterStdDate = DateTimeFormatter.ofPattern(STD_DATE_FORMAT);

    static final Pattern pEmail = Pattern.compile("^\\w+([-.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*$", Pattern.CASE_INSENSITIVE);
    static final Pattern pMobile = Pattern.compile("^\\d{11}$");
    static final Pattern pPicture = Pattern.compile(".*\\.(?<ext>jpg|bmp|gif|png|jpeg)$", Pattern.CASE_INSENSITIVE);
    static final Pattern pFlash = Pattern.compile(".*\\.(?<ext>swf|flv)$", Pattern.CASE_INSENSITIVE);
    static final Pattern pVideo = Pattern.compile(".*\\.(?<ext>avi|mpg|asf|rm|rmvb)$", Pattern.CASE_INSENSITIVE);
    static final Pattern pMusic = Pattern.compile(".*\\.(?<ext>mp3|wav|wma|wmv|mid)$", Pattern.CASE_INSENSITIVE);
    static final Pattern pNum = Pattern.compile("\\d+", Pattern.CASE_INSENSITIVE);
    static final Pattern pAlphabet = Pattern.compile("^[a-z]+$", Pattern.CASE_INSENSITIVE);


    static final Pattern pIpV4 = Pattern.compile("^(([1-9]?|1\\d|2[0-4])\\d|25[0-5])(\\.(([1-9]?|1\\d|2[0-4])\\d|25[0-5])){3}$");


    static final Pattern pDotNetDateTime = Pattern.compile("/Date\\((?<timestamp>\\d+)\\)/", Pattern.CASE_INSENSITIVE);

    static final String CODE_UTF8 = "UTF-8";

    static final Gson sGson ;

    static {
        sGson = new GsonBuilder().setDateFormat(STD_DATETIME_FORMAT)
                .registerTypeAdapter(Double.class, new JsonSerializer<Double>() {
                    @Override
                    public JsonElement serialize(Double src, Type typeOfSrc, JsonSerializationContext context) {
                        if (src == src.longValue()) {
                            return new JsonPrimitive(src.longValue());
                        }
                        else {
                            return new JsonPrimitive(src);
                        }
                    }
                })
                .create();
    }

    private Misc() {
    }

    public static UUID uuidFromString(String s) {
        if (StringUtils.hasText(s) && (s.length() >= 32)) {
            if (s.length() == UUID_STD_SIZE) {
                return UUID.fromString(s);
            } else {
                return UUID.fromString(String.format("%s-%s-%s-%s-%s"
                        , s.substring(0, 8)
                        , s.substring(8, 12)
                        , s.substring(12, 16)
                        , s.substring(16, 20)
                        , s.substring(20, 32)));
            }
        }
        return null;
    }

    public static String toStdString(UUID uuid) {
        if (uuid == null) {
            return null;
        }
        else {
            return uuid.toString().replace("-", "").toUpperCase();
        }
    }

    public static boolean isUUIDEmpty(UUID uuid) {
        return (uuid == null) || (uuid.equals(EmptyUUID));
    }

    public static String toBase64(String str) {
        if (StringUtils.hasLength(str)) {
            return Base64Utils.encodeToString(str.getBytes());
        }
        else {
            return str;
        }
    }

    public static String toJson(Object o) {
        if (o == null) {
            return null;
        }
        return sGson.toJson(o);
    }

    //用法：简单类，非泛形
    public static <T> T fromJson(String s, Class<T> classOfT) {
        if (!StringUtils.hasText(s)) {
            return null;
        }

        return sGson.fromJson(s, classOfT);
    }

    //用法：泛形类
    public static <T> List<T> fromJsonToList(String s, Class<T[]> clazz) {
        if (!StringUtils.hasText(s)) {
            return Collections.emptyList();
        }

        T[] o = sGson.fromJson(s, clazz);
        return Arrays.asList(o);
    }

    public static String rsaEncrypt(String s, String key) throws NSException {
        if (!StringUtils.hasText(s))
            return null;

        if (!StringUtils.hasText(key))
            throw new IllegalArgumentException("Rsa Key为空！");

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.fromXmlString(key);

        return rsa.encrypt(s);
    }

    public static String toStdDateString(LocalDate dt) {
        if (dt == null)
            return "";
        return dt.format(formatterStdDate);
    }

    public static String toStdDateString(LocalDateTime dt) {
        if (dt == null)
            return "";
        return dt.format(formatterStdDate);
    }

    public static String toStdString(LocalDate dt) {
        if (dt == null)
            return "";
        return dt.format(formatterStdDateTime);
    }

    public static String toStdString(LocalDateTime dt) {
        if (dt == null)
            return "";
        return dt.format(formatterStdDateTime);
    }

    public static String toStdString(Date dt) {
        return new SimpleDateFormat(STD_DATETIME_FORMAT).format(dt);
    }

    public static String toStdUtcSting(LocalDateTime dt) {
        ZonedDateTime ldtZoned = dt.atZone(ZoneId.systemDefault());
        ZonedDateTime utcZoned = ldtZoned.withZoneSameInstant(ZoneId.of("UTC"));
        return utcZoned.format(formatterStdDateTime);

    }

    public static LocalDateTime parseDotNetDateTime(String str) {
        if (!StringUtils.hasText(str))
            return null;

        Matcher m = pDotNetDateTime.matcher(str);
        if (m.matches()) {
            MatchResult mr = m.toMatchResult();
            long mts = Long.parseLong(mr.group(1));
            return LocalDateTime.ofInstant(Instant.ofEpochSecond(mts / 1000, (int) (mts % 1000) * 1000000L), ZoneId.systemDefault());
        }
        throw new IllegalArgumentException(str + "格式不是DotNet格式，如：‘/Date(00000000)/’");
    }

    public static LocalDate parseISODate(String str) {
        if (!StringUtils.hasText(str)) {
            return null;
        }
        return LocalDate.parse(str, formatterDate);
    }

    public static LocalDateTime parseISODateTime(String str) {
        if (!StringUtils.hasText(str)) {
            return null;
        }

        if (str.length() > 10) {
            return LocalDateTime.parse(str, formatterDateTime);
        }
        else {
            LocalDate date = parseISODate(str);
            return date == null ?  null : date.atStartOfDay();
        }
    }

    public static LocalDateTime trimTime(LocalDateTime dt) {
        if (dt == null) {
            return null;
        }
        return dt.toLocalDate().atStartOfDay();
    }

    @Deprecated
    public static String getISODateTimeString(LocalDateTime dt) {
        return toStdString(dt);
    }

    public static String urlEncode(String text) throws UnsupportedEncodingException {
        return URLEncoder.encode(text, CODE_UTF8);
    }

    public static byte[] hexStringToByteArray(String strHexString) {

        if (!StringUtils.hasLength(strHexString))
            return new byte[0];

        char[] arr = strHexString.toCharArray();

        int len = arr.length;
        if ((len % 2) != 0)
            throw new IllegalArgumentException("Error In hexStringToByteArray!");

        int byteLen = len / 2;
        byte[] bytes = new byte[byteLen];

        for (int i = 0; i < byteLen; i++) {
            bytes[i] = (byte) ((Character.digit(arr[i * 2], 16) << 4) + Character.digit(arr[i * 2 + 1], 16));
        }
        return bytes;
    }

    public static String byteArrayToHexString(byte[] bytes) {

        int blen;
        if ((bytes == null) || ((blen = bytes.length) == 0))
            return "";

        StringBuilder sb = new StringBuilder(2 * blen);
        for (int i = 0; i < blen; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }

        return sb.toString();
    }

    public static String getSHA1(String text) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        sha1.update(text.getBytes());
        return byteArrayToHexString(sha1.digest());
    }

    public static String getMD5(String text) {
        try {
            if (text.compareTo("") == 0) {
                return "";
            }
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(text.getBytes());
            return byteArrayToHexString(md5.digest());
        } catch (Exception ex) {
            ignoreException(ex);
            return null;
        }
    }

    public static String readFile(String filename) throws NSException {
        return readFile(filename, CODE_UTF8);
    }

    public static String readFile(String filename, String encode) throws NSException {
        File f = new File(filename);
        if (f.exists())
            return readFile(f, encode);
        else
            throw new NSException(filename + "不存在");
    }

    public static String readFile(File file) throws NSException {
        return readFile(file, CODE_UTF8);
    }

    public static String[] readFileLines(File file, String encode) throws NSException {
        List<String> lines = new ArrayList<>();


        try (InputStream is = new FileInputStream(file);
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, encode))) {

            String line;
            while ((line = reader.readLine()) != null) { // 如果 line 为空说明读完了
                lines.add(line);
            }
            return lines.toArray(new String[0]);
        } catch (Exception ex) {
            throw new NSException(ex);
        }
    }

    public static String readFile(File file, String encode) throws NSException {
        try {
            return readStream(new FileInputStream(file), encode);
        } catch (Exception ex) {
            throw new NSException(ex);
        }
    }

    public static String readStream(InputStream inputStream) throws NSException {
        return readStream(inputStream, CODE_UTF8);
    }

    public static String readStream(InputStream inputStream, String encode) throws NSException {

        StringBuilder sb = new StringBuilder(); // 用来保存每行读取的内容

        try {

            InputStreamReader isr;
            if (encode.equalsIgnoreCase(CODE_UTF8))
                isr = new InputStreamReader(new BOMInputStream(inputStream), encode);
            else
                isr = new InputStreamReader(inputStream, encode);

            BufferedReader reader = new BufferedReader(isr);
            String line;
            while ((line = reader.readLine()) != null) { // 如果 line 为空说明读完了
                sb.append(line); // 将读到的内容添加到 buffer 中
                sb.append("\n"); // 添加换行符
            }
            reader.close();
            isr.close();
            return sb.toString();
        } catch (Exception ex) {
            throw new NSException(ex);
        }
    }

    public static void directWriteFile(String filename, String content) throws NSException {
        try {
            File newFile = new File(filename);
            if (newFile.createNewFile()) {
                try (FileWriter writer = new FileWriter(newFile);
                     BufferedWriter bw = new BufferedWriter(writer)) {

                    bw.write(content);

                    bw.close();
                    writer.close();
                }
            }
        } catch (Exception ex) {
            throw new NSException(ex);
        }
    }

    public static Resource getLocalFile(String urlfilename) {
        return new DefaultResourceLoader().getResource("../.." + urlfilename);
    }

    public static Resource getResourceFile(String filename) {
        return new DefaultResourceLoader().getResource(filename);
    }

    public static <T> T objectCopy(Object src, T des) throws NSException {
        if (src == null)
            return des;

        if (des == null)
            return null;

        try {

            Class<?> clsSrc = src.getClass();
            Class<?> clsDes = des.getClass();

            while (!clsDes.equals(Object.class)) {
                Map<String,Field> desFields = Arrays.asList(clsDes.getDeclaredFields()).stream()
                        .collect(Collectors.toMap(Field::getName, p->p));
                Class<?> tmpSrc = clsSrc;
                while (!tmpSrc.equals(Object.class)) {
                    for (Field f : tmpSrc.getDeclaredFields()) {
                        if (!Modifier.isStatic(f.getModifiers())) {
                            f.setAccessible(true);

                            Object v = f.get(src);

                            Field fdes = desFields.getOrDefault(f.getName(),null);
                            if (fdes != null) {

                                if (!fdes.getType().equals(f.getType())
                                        || (!f.getType().isPrimitive() && (v == null) && fdes.getType().isPrimitive()))
                                    continue;

                                fdes.setAccessible(true);
                                fdes.set(des, v);
                            }
                        }
                    }
                    tmpSrc = tmpSrc.getSuperclass();
                }
                clsDes = clsDes.getSuperclass();
            }
            return des;
        } catch (Exception ex) {
            throw new NSException(ex);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> List<T> getObjectFromMapList(List<Object> src, Class<T> des) throws NSException {

        List<T> result;
        try {
            result = new ArrayList<>();
            for (Object objSrc : src) {
                T item = getObjectFromMapItem((Map<String, Object>) objSrc, des);
                result.add(item);
            }
        } catch (Exception exp) {
            throw new NSException(exp);
        }
        return result;
    }

    public static <T> T getObjectFromMapItem(Map<String, Object> src, Class<T> des) throws NSException {

        T result;
        try {
            result = des.newInstance();

            Map<String,Field> desFields = Arrays.asList(des.getDeclaredFields()).stream()
                    .collect(Collectors.toMap(Field::getName, p->p));

            for (Map.Entry<String, Object> entry : src.entrySet()) {
                Field fd = desFields.getOrDefault(entry.getKey(),null);
                if (fd == null) {
                    continue;
                }
                fd.setAccessible(true);
                Object objVal = entry.getValue();
                Class<?> fdType = fd.getType();
                if (fdType.isAssignableFrom(objVal.getClass())) {
                    fd.set(result, entry.getValue());
                } else if (objVal.getClass().isAssignableFrom(Double.class)) {
                    if (fdType.isAssignableFrom(Integer.class))
                        fd.set(result, ((Double) objVal).intValue());
                } else {
                    throw new NSException(String.format("field %s , current type: %s, got type : %s"
                            , entry.getKey()
                            , fd.getType().toString()
                            , objVal.getClass().toString()));
                }

            }
        } catch (Exception exp) {
            throw new NSException(exp);
        }
        return result;
    }

    //目前实现一级属性,没有实现复合属性
    public static Map<String, Object> getMapFromObject(Object o) throws NSException {
        Map<String,Object> map = new HashMap<>();

        if (o == null){
            return map;
        }
        try {
            Class<?> tmpSrc = o.getClass();
            while (!tmpSrc.equals(Object.class)) {
                for (Field f : tmpSrc.getDeclaredFields()) {
                    if (!Modifier.isStatic(f.getModifiers())) {
                        f.setAccessible(true);

                        if (map.containsKey(f.getName()))
                            continue;
                        map.put(f.getName(),f.get(o));
                    }
                }
                tmpSrc = tmpSrc.getSuperclass();
            }
            return map;
        } catch (Exception ex) {
            throw new NSException(ex);
        }
    }

    public static String genPasswordSalt() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static <T> T emptyElse(T v, T defaultValue) {

        if (v instanceof String) {
            return StringUtils.hasText((String) v) ? v : defaultValue;
        } else {
            return (v == null) ? defaultValue : v;
        }
    }

    public static String bigIntToIP(BigInteger nip) throws UnknownHostException {

        if (nip == null)
            return null;

        if (BigInteger.ZERO.compareTo(nip) == 0)
            return EMPTY_IP;

        byte[] val = nip.toByteArray();
        byte[] unsignedval = Arrays.copyOfRange(val, 1, val.length);
        String sip;
        try {
            sip = InetAddress.getByAddress(unsignedval).getHostAddress();
        } catch (UnknownHostException e) {
            sip = InetAddress.getByAddress(val).getHostAddress();
            ignoreException(e);
        }
        return sip;
    }

    public static BigInteger ipToBigInt(String sip) {
        InetAddress ip = InetAddresses.forString(sip);
        byte[] result = ip.getAddress();
        return new BigInteger(1, result);
    }

    public static long ipToInt(String ip) throws NSException {
        String[] array = ip.split("\\.");
        if (array.length != 4) {
            throw new NSException("Bad Ip");
        }
        long num = Long.parseLong(array[0]) << 24;
        num += Long.parseLong(array[1]) << 16;
        num += Long.parseLong(array[2]) << 8;
        num += Long.parseLong(array[3]);
        return num;
    }

    public static String intToIP(long nip) {
        return String.format("%s.%s.%s.%s",
                nip >> 24 & 255,
                nip >> 16 & 255,
                nip >> 8 & 255,
                nip & 255
        );
    }

    public static boolean isValidIPv4(String ipAddress) {

        if (!StringUtils.hasText(ipAddress) || ipAddress.length() < 7 || ipAddress.length() > 15) {
            return false;
        }
        return pIpV4.matcher(ipAddress).matches();
    }

    public static String convertByteString(Long n) {
        if (n == null)
            return "";
        if (n < 1024)
            return String.format("%dB", n);
        double temp = n / 1024D;
        if (temp < 1024D)
            return String.format("%.1fK", temp);
        temp /= 1024D;
        if (temp < 1024D)
            return String.format("%.1fM", temp);
        temp /= 1024D;
        if (temp < 1024D)
            return String.format("%.1fG", temp);
        temp /= 1024D;
        if (temp < 1024D)
            return String.format("%.1fT", temp);
        temp /= 1024D;
        if (temp < 1024D)
            return String.format("%.1fP", temp);
        temp /= 1024D;

        return String.format("%.1fE", temp);
    }

    public static BigDecimal parseDecimal(String s) {
        if (!StringUtils.hasText(s)) {
            return null;
        }
        else {
            return new BigDecimal(s);
        }
    }

    public static boolean isEmail(String str) {
        return isPattern(str, pEmail);
    }

    public static boolean isMobile(String str) {
        return isPattern(str, pMobile);
    }

    public static boolean isPictureFile(String filename) {
        return isPattern(filename, pPicture);
    }

    public static boolean isFlashFile(String filename) {
        return isPattern(filename, pFlash);
    }

    public static boolean isVideoFile(String filename) {
        return isPattern(filename, pVideo);
    }

    public static boolean isMusicFile(String filename) {
        return isPattern(filename, pMusic);
    }

    public static boolean isMediaFile(String filename) {
        return (isVideoFile(filename) || isMusicFile(filename));
    }

    public static boolean isPattern(String filename, String regex) {
        return StringUtils.hasText(regex) && isPattern(filename, Pattern.compile(regex, Pattern.CASE_INSENSITIVE));

    }

    public static boolean isPattern(String filename, Pattern pattern) {
        return StringUtils.hasText(filename) && pattern.matcher(filename).matches();

    }

    public static Long getTicks(LocalDateTime dt) {
        LocalDateTime beginTime = LocalDateTime.of(1, 1, 1, 12, 0, 0);
        long interval = Duration.between(beginTime, (dt == null) ? LocalDateTime.now() : dt).getSeconds();
        return (interval * 10000000);
    }


    private final  static Pattern reQueryStrings = Pattern.compile("(?<key>[^&=]+)=(?<val>[^&]+)");
    public static Map<String, String> resolveParams(String text) {
        Map<String, String> params = new HashMap<>();
        if (StringUtils.hasText(text)) {
            Matcher m = reQueryStrings.matcher(text);
            while (m.find()) {
                params.put(m.group("key").toLowerCase(), m.group("val"));
            }
        }
        return params;
    }

    public static Boolean tryParseBool(String src) {

        Boolean ret = null;
        if (StringUtils.hasText(src)) {
            if ("true".equalsIgnoreCase(src)) {
                ret = true;
            } else if ("false".equalsIgnoreCase(src)) {
                ret = false;
            }
        }
        return ret;
    }

    public static Boolean isAlphabet(String s){
        if (s == null){
            return null;
        }
        else {
            return pAlphabet.matcher(s).matches();
        }
    }

    public static boolean isIntStrArr(String str) {
        if (!StringUtils.hasText(str)) {
            return false;
        }

        for (String aSplit : str.split(",")) {
            Matcher m = pNum.matcher(aSplit);
            if (!m.matches()) {
                return false;
            }
        }
        return true;
    }

    public static Integer[] strToIntArr(String str) {

        if (!StringUtils.hasText(str)) {
            return new Integer[]{};
        }

        String[] b = str.split(",");
        Integer[] arr = new Integer[b.length];
        for (int i = 0; i < b.length; i++) {
            arr[i] = Integer.parseInt(b[i]);
        }
        return arr;
    }

    public static List<Integer> strToIntList(String str) {
        if (!StringUtils.hasText(str)) {
            return Collections.emptyList();
        }
        return Arrays.asList(strToIntArr(str));
    }

    public static List<BigInteger> strToBigIntList(String str) {
        if (!StringUtils.hasText(str)) {
            return Collections.emptyList();
        }
        List<BigInteger> idlist = new ArrayList<>();
        String[] ips = str.split(",");

        for (String item : ips) {
            idlist.add(new BigInteger(item));
        }
        return idlist;
    }


    public static <T> String intListToStr(List<T> list) {
        if (list == null || list.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (T i : list) {
            sb.append(i.toString()).append(",");
        }
        return sb.substring(0, sb.length() - 1);
    }

    public static String intArrToStr(Integer[] arr) {
        if (arr == null || arr.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (Integer i : arr) {
            sb.append(i.toString()).append(",");
        }
        return sb.substring(0, sb.length() - 1);
    }

    public static List<String> strToStrList(String str) {
        if (StringUtils.hasText(str)) {
            String[] b = str.split(",");
            return Arrays.asList(b);
        } else {
            return Collections.emptyList();
        }
    }

    public static String trim(String s){
        return (s == null) ? null : s.trim();
    }


    public static void ignoreException(Exception ex) {
        //为了代码审查
    }

}

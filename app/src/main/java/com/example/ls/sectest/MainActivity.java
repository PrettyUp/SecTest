package com.example.ls.sectest;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;


public class MainActivity extends AppCompatActivity {
    static byte[] key;
    byte[] byte_encrypt_result;
    byte[] byte_decrypt_result;
    byte[] byte_et_encrypt_text;
    String key_str;

    // Used to load the 'native-test' library on application startup.
    static {
        // System.loadLibrary("native-lib");
        System.loadLibrary("native-test");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 获取当前上下文
        Context context = getApplicationContext();
        // 发布apk时用来签名的keystore中查看到的sha1值，改成自己的
        String cert_sha1 = "937FF2936CDB81EEF4A776290EA9E076B3BC03A9";
        // 调用isOrgApp()获取比较结果
        boolean is_org_app = isOrgApp(context,cert_sha1);
        // 如果比较初始从证书里查看到的sha1，与代码获取到的当前证书中的sha1不一致，那么就自我销毁
        if(! is_org_app){
            android.os.Process.killProcess(android.os.Process.myPid());
        }


        final EditText et_encrypt = findViewById(R.id.et_encrypt);
        Button btn_encrypt = findViewById(R.id.btn_encrypt);
        Button btn_decrypt = findViewById(R.id.btn_decrypt);
        final TextView tv_result = findViewById(R.id.tv_result);

        btn_encrypt.setOnClickListener(new View.OnClickListener()
        {
            public void onClick(View paramAnonymousView)
            {
                try {
                    key_str = getAESKey();
                    key = hexStrToByteArray(key_str);
                    // 从编缉框获取文本内容
                    byte_et_encrypt_text = et_encrypt.getText().toString().getBytes("ISO8859-1");
                    // 对获取到的文本内容进行AES加密，获取返回的byte[]型加密结果
                    byte_encrypt_result = AESCoder.encrypt(byte_et_encrypt_text, key);
                    // 将架密结果转成字符串输出到文本框
                    tv_result.setText(new String(byte_encrypt_result, "ISO8859-1"));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        btn_decrypt.setOnClickListener(new View.OnClickListener()
        {
            public void onClick(View paramAnonymousView)
            {
                try {

                    key_str = getAESKey();

                    key = hexStrToByteArray(key_str);
                    // 从文本框获取文本内容
                    byte_encrypt_result = tv_result.getText().toString().getBytes("ISO8859-1");
                    // 对获取到的文本内容进行AES解密，获取返回的byte[]型解密结果
                    byte_decrypt_result = AESCoder.decrypt(byte_encrypt_result, key);
                    // 将解密结果转成字符串输出到文本框
                    tv_result.setText(new String(byte_decrypt_result, "ISO8859-1"));

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    // 此函数用于返回比较结果
    public static boolean isOrgApp(Context context,String cert_sha1){
        String current_sha1 = getAppSha1(context,cert_sha1);
        // 返回的字符串带冒号形式，用replace去掉
        current_sha1 = current_sha1.replace(":","");
        return current_sha1.equals(current_sha1);
    }
    // 此函数用于获取当前APP证书中的sha1值
    public static String getAppSha1(Context context,String cert_sha1) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            byte[] cert = info.signatures[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] publicKey = md.digest(cert);
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < publicKey.length; i++) {
                String appendString = Integer.toHexString(0xFF & publicKey[i]).toUpperCase(Locale.US);
                if (appendString.length() == 1)
                    hexString.append("0");
                hexString.append(appendString);
                hexString.append(":");
            }
            String result = hexString.toString();
            return result.substring(0, result.length()-1);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String byteArrayToHexStr(byte[] byteArray) {
        if (byteArray == null){
            return null;
        }
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexStrToByteArray(String str)
    {
        if (str == null) {
            return null;
        }
        if (str.length() == 0) {
            return new byte[0];
        }
        byte[] byteArray = new byte[str.length() / 2];
        for (int i = 0; i < byteArray.length; i++){
            String subStr = str.substring(2 * i, 2 * i + 2);
            byteArray[i] = ((byte)Integer.parseInt(subStr, 16));
        }
        return byteArray;
    }

    // public native String stringFromJNI();
    // public native String stringFromJNITest();
    public native String getAESKey();
}


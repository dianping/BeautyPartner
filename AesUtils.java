

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class AesUtils
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AesUtils.class);

    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";

    private static KeyGenerator keyGen;

    private static Cipher cipher;

    static
    {
        init();
    }

    private static void init()
    {
        try
        {
            keyGen = KeyGenerator.getInstance("AES");
        }
        catch (NoSuchAlgorithmException e)
        {
            LOGGER.error("[AesUtils] init KeyGen error" ,e);
        }
        keyGen.init(128);
        try
        {
            cipher = Cipher.getInstance(ALGORITHM);
        }
        catch (Exception e)
        {
            LOGGER.error("[AesUtils] init cihper error" ,e);
        }
    }

    /**
     * 功能描述：加密并BASE64编码<p>
     *
     */
    public static String encryptBase64(String content, String keyString)
    {
        String encryptText = null;
        Key key = new SecretKeySpec(keyString.getBytes(), "AES");
        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        catch (InvalidKeyException e)
        {
            LOGGER.error("[AesUtils] invalid key " + keyString, e);
        }
        try
        {
            byte[] encryptBytes = cipher.doFinal(content.getBytes());
            encryptText = new String(Base64.encodeBase64(encryptBytes));
        }
        catch (Exception e)
        {
            LOGGER.error("[AesUtils] encrypt error ", e);
        }
        return encryptText;
    }

    /**
     * 功能描述：从BASE64字符串解密<p>
     */
    public static String decryptBase64(String content, String keyString)
    {
        String decryptText = null;
        Key key = new SecretKeySpec(keyString.getBytes(), "AES");
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        catch (InvalidKeyException e)
        {
            LOGGER.error("[AesUtils]invalid key" + keyString ,e);
        }
        try
        {
            byte[] encryptBytes = Base64.decodeBase64(content.getBytes());
            byte[] decryptBytes = cipher.doFinal(encryptBytes);
            decryptText = new String(decryptBytes);
        }
        catch (IllegalBlockSizeException e)
        {
            LOGGER.error("[AesUtils]invalid key" + keyString ,e);
        }
        catch (BadPaddingException e)
        {
            LOGGER.error("[AesUtils]invalid key" + keyString ,e);
        }
        return decryptText;
    }
}

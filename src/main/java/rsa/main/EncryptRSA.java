package rsa.main;


import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptRSA{

  static {
    Security.addProvider((Provider) new BouncyCastleProvider());
  }

  
  public static void main(String[] args)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
      IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, GeneralSecurityException {

  

   
    String publicKey ="MIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgB29Ugxw/bpNlFlLMrP8IE4e1zHtCk4u6O7QEcw7b0GML+AACTv8pDipzrS34dlNJHJHSZ8vgrQCJFA3gm310+bE8V1JeJ9QKK+G1GtsFBVwCgBjHLdlNmcXpYUDQeX0oMi8ts5Nm1cIr1bWrEeabPnsLoFs4VEfho+5/kpto5bwjnKwHO92zCBvDrCaYILJQLgvbCKT8WRLe37jBGApdPjhK05DfFoh52cJVbjhu0KOuHanvx0begI7ApBiybleo6vxgOW4Oo46+I9qNqof5zrYRlJYHY087VH+eRA7R2+VjfeAWLh/qBs4vwZxvDfWe/9IeHn+2LRUGF7faPmHajYF+8ikfhK6i742DzkqgD1MYtZHOzYsWE9W8+rASh8ijmeHVt1mbbiibMoahnhB/S8Yl+NjCqBKldBKaeIIoZPsyrEDF5iHYV1ll3k0d70NzKnIPaHaaYY8EjKaA4gznsxfE1xOOBjYuhhC1xYwrgrd5G5fGwvHMxDSYQ3phPAZaRlqeErpz+elZkNEWuba2F7H4rWcEb2OMlG1sirquQlXQc1POE8ikE72gpgZpLoLFVPqs4VeMZJoZnXgHuMGb0+hBbW4gEBitaOHH9RsxCdjLuvZJ2dHKbRblRxb3DggwnsUTM/QtXhutE0nqhPMj+nrSfj5VQFYFN6lEfqK4EvPwIDAQAB";
    String content = "hello";
 
        byte[] encryptedKey = asymmetric_encrypt("hellow".getBytes(), publicKey.getBytes(), "RSA","RSA");
        
        byte[] enc=encodeToBase64(encryptedKey);
        System.out.println(new String(enc));
  }

  public static byte[] asymmetric_encrypt(byte[] content, byte[] publicKey, String encryptionMode, String encryptionAlgo) throws GeneralSecurityException {
      PublicKey x509Key = getPublic(publicKey, encryptionMode);
      return helper_encrypt(content, x509Key, encryptionAlgo);
    }
  
  public static PublicKey getPublic(byte[] publicKey, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException {
      X509EncodedKeySpec spec = new X509EncodedKeySpec(decodeFromBase64(publicKey));
      KeyFactory kf = KeyFactory.getInstance(mode);
      return kf.generatePublic(spec);
    }
  
  public static byte[] helper_encrypt(byte[] input, PublicKey key, String cipherAlgorithm) throws GeneralSecurityException {
      Cipher cipher = Cipher.getInstance(cipherAlgorithm);
      cipher.init(1, key);
      return cipher.doFinal(input);
    }
  
  public static byte[] decodeFromBase64(byte[] input) {
      return Base64.getDecoder().decode(input);
    }
  
  public static byte[] encodeToBase64(byte[] input) {
      return Base64.getEncoder().encode(input);
    }
  


}

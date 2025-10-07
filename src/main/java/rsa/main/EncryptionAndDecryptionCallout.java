package rsa.main;

import java.security.Security;
//import java.util.Base64;
import java.util.Map;
//import java.rmi.server.Operation;
//import java.security.GeneralSecurityException;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.KeyFactory;
//import java.security.NoSuchAlgorithmException;
//import java.security.PrivateKey;
//import java.security.Provider;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.Security;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Arrays;
//import java.util.Base64;
//import java.util.Map;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

//import encryption.ContentLogger;


public class EncryptionAndDecryptionCallout implements Execution {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	private Map<String, String> properties = null;

	public EncryptionAndDecryptionCallout(Map<String, String> properties) {
		this.properties = properties;
	}

	public ExecutionResult execute(MessageContext msgContext, ExecutionContext execContext) {
		long executionStartTime = System.nanoTime();
		try {

			DebugLogger debugLogger = new DebugLogger(msgContext, execContext);
//			ContentLogger contentLogger = new ContentLogger(msgContext, execContext);
			debugLogger.log("msg1", "In init()");
			String aesKey = resolveVariable(this.properties.get("aesKey"), msgContext);
			String rsaKey = resolveVariable(this.properties.get("rsaKey"), msgContext);
			String msg = resolveVariable(this.properties.get("msg"), msgContext);
			String operation = resolveVariable(this.properties.get("mode"), msgContext);
			String IV = resolveVariable(this.properties.get("iv"), msgContext);
			debugLogger.log("msg3", msg);
			if (operation.equals("enc")) {
				RSA_Crypto o = new RSA_Crypto();
				IV = o.getSaltString();
				msgContext.setVariable("IV", new String(IV));
				byte[] encaes = o.encryptAES(msg, IV, aesKey);
				msgContext.setVariable("EncryptedData:", new String(encaes));

				byte[] encryptedKey = EncryptRSA.asymmetric_encrypt(aesKey.getBytes(), rsaKey.getBytes(), "RSA", "RSA");
				msgContext.setVariable("EncryptedKey:", new String(encryptedKey));
			}

			else if (operation.equals("decr")) {
				RSA_Crypto o = new RSA_Crypto();
				String EncData = aesKey;
				String privateKey = rsaKey;
				String content = msg;
				byte[] dec = DecryptRSA.decodeFromBase64(EncData.getBytes());
				byte[] decryptedKey = DecryptRSA.asymmetric_decrypt(dec, privateKey.getBytes(), "RSA", "RSA");
				String ori = o.decryptAES(content.getBytes(), IV, new String(decryptedKey));
				msgContext.setVariable("OriginalMessage", ori);
			}

			long executionEndTime = System.nanoTime();
			debugLogger.log("ENCRYPTION_EXECUTION_TIME", String.valueOf(executionEndTime - executionStartTime));
			return ExecutionResult.SUCCESS;
		} catch (Exception exception) {
			DebugLogger debugLogger = new DebugLogger(msgContext, execContext);
			msgContext.setVariable("CATCH_EXCEPTION", exception.getMessage());
			long executionEndTime = System.nanoTime();
			debugLogger.log("ENCRYPTION_EXECUTION_TIME", String.valueOf(executionEndTime - executionStartTime));
			return ExecutionResult.ABORT;
		}
	}

	private String resolveVariable(String variable, MessageContext msgContext) {
		if (isEmpty(variable))
			return "";
		if (!variable.startsWith("{") || !variable.endsWith("}"))
			return variable;
		String value = msgContext.getVariable(variable.substring(1, variable.length() - 1)).toString();
		if (isEmpty(value))
			return variable;
		return value;
	}

	private boolean isEmpty(String variable) {
		return (variable == null || variable.length() == 0);
	}

	public EncryptionAndDecryptionCallout() {
	}

}

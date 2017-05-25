package aau.ISO9796SignerVerifier;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2Signer;
import org.bouncycastle.util.encoders.Base64;

/**
 * Wrapper for the ISO9796-2 bouncycastle (https://www.bouncycastle.org/) sign
 * and verify functions for Message Recovery from signatures
 * 
 * ISO Standard: http://www.sarm.am/docs/ISO_IEC_9796-2_2002(E)-Character_PDF_document.pdf 
 * Algorithm: RSA 
 * Hash: SHA-1 
 * Padding: ISO-9796-2 Scheme 2
 * 
 * Example usage: 
 * verify signature from file:
 *  java -jar -f verify -i signature.out -k publicKey.der -file
 *  
 * sign message to stdout
 *	java -jar -f sign -i "this is the message" -k privateKey.der
 *
 * KEY GENERATION:
 *  
 * Key generations Generate a 2048-bit RSA private key 
 * $ openssl genrsa -out privateKey.pem 2048 
 * 
 * Convert privateKey to PKCS#8 format 
 * $ openssl pkcs8 -topk8 -inform PEM -outform DER -in privateKey.pem -out privateKey.der -nocrypt 
 * 
 * Output public key in DER format
 * $ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
 * 
 */

public class App {
	private static String publicKeyFilename = null;
	private static String privateKeyFilename = null;
	private static byte[] signature = null;
	private static byte[] message = null;
	private static String function = null;
	private static boolean file;

	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		if (parseInput(args)) {
			if (function.equals("verify")) {
				try {
					if (file) {
						signature = readSignatureFromFile("signature.out");
					}
					String msg = verify();
					System.out.println(msg);
				} catch (Exception e) {
					System.err.println("Error during verification!");
					e.printStackTrace();
				}
			}

			else if (function.equals("sign")) {
				try {
					byte[] sig = sign();
					if (file) {
						writeSignatureToFile(sig);
					}

					byte [] output = Base64.encode(sig);
					
					System.out.println((new String(output)));

				} catch (Exception e) {
					System.err.println("Error during signature generation!");
					e.printStackTrace();
				}
			}
		}

	}

	private static String verify() throws Exception {
		RSAEngine engine = new RSAEngine();
		Digest digest = new SHA1Digest();

		ISO9796d2Signer verifier = new ISO9796d2Signer(engine, digest, true);
		RSAPublicKey publicKey = (RSAPublicKey) getPublic(publicKeyFilename);
		BigInteger big = ((RSAKey) publicKey).getModulus();
		RSAKeyParameters rsaPublic = new RSAKeyParameters(false, big, publicKey.getPublicExponent());
		verifier = new ISO9796d2Signer(engine, digest, true);
		verifier.init(false, rsaPublic); // false for verify

		if (!verifier.verifySignature(signature)) {
			System.err.println("Signature was modified, could not verify correctness!");
			return "";
		}
		String recoveredMessage = "";
		try {
			if (verifier.hasFullMessage()) {
				verifier.updateWithRecoveredMessage(signature);

			}
			byte[] message = verifier.getRecoveredMessage();
			recoveredMessage = new String(message, "UTF-8");
		} catch (Exception exception) {
			System.err.println("Recover failed!");
		}

		return recoveredMessage;
	}

	private static byte[] sign() throws Exception {
		RSAEngine rsa = new RSAEngine();
		Digest dig = new SHA1Digest();

		RSAPrivateKey privateKey = (RSAPrivateKey) getPrivate(privateKeyFilename);
		BigInteger big = ((RSAKey) privateKey).getModulus();
		ISO9796d2Signer eng = new ISO9796d2Signer(rsa, dig, true);
		RSAKeyParameters rsaPriv = new RSAKeyParameters(true, big, privateKey.getPrivateExponent());
		eng.init(true, rsaPriv);
		eng.update(message[0]);
		eng.update(message, 1, message.length - 1);

		byte[] signature = eng.generateSignature();

		return signature;
	}

	private static PublicKey getPublic(String filename) throws Exception {

		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	private static PrivateKey getPrivate(String filename) throws Exception {

		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	private static void writeSignatureToFile(byte[] signature) {
		Path file = Paths.get("signature.out");
		byte [] output = Base64.encode(signature);
		try {
			Files.write(file, output);
		} catch (IOException e) {
			System.err.println("Could not write signature file");
			e.printStackTrace();
		}
	}

	private static byte[] readSignatureFromFile(String filePath) {
		File file = new File(filePath);
		byte[] keyBytes = null;
		try {
			keyBytes = Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			System.err.println("Could not read signature file");
			e.printStackTrace();
		}
		byte [] input = Base64.decode(keyBytes);
		return input;
	}
	
	private static boolean parseInput(String[] args) {
		String[] validFunctions = { "verify", "sign" };
		Options options = createCLI();		
		
		CommandLineParser parser = new DefaultParser();
	        HelpFormatter formatter = new HelpFormatter();
	        CommandLine cmd;

	        try {
	            cmd = parser.parse(options, args);
	        } catch (ParseException e) {
	            System.out.println(e.getMessage());
	            formatter.printHelp("utility-name", options);
	            return false;
	        }

	        if (!Arrays.stream(validFunctions).parallel().anyMatch(cmd.getOptionValue("function")::contains)) {
	        	return false;
	        }
	        
	        function = cmd.getOptionValue("function");
	        
	        String input = cmd.getOptionValue("input");
	        String key = cmd.getOptionValue("key");
	        if(cmd.hasOption("file")) {
	            file = true;
	        }
	       	        
	        if(function.contains("verify")){
	        	if(file){
	        		signature = readSignatureFromFile(input);
	        	}
	        	else {
		        	signature = Base64.decode(input.getBytes());
		        }
	        	publicKeyFilename = key;
	        }
	        
	        else if (function.contains("sign")) {
				message = input.getBytes();
				privateKeyFilename = key;			
			}
	        
	        return true;
	}
	
	private static Options createCLI(){
		Options options = new Options();

        Option function = new Option("f", "function", true, "either verify or sign");
        function.setRequired(true);
        options.addOption(function);

        Option input = new Option("i", "input", true, "signature input either file or string or message to sign. base 64 encoded");
        input.setRequired(true);
        options.addOption(input);   
        
        Option key = new Option("k", "key", true, "pulickey or private key path");
        key.setRequired(true);
        options.addOption(key); 
        
        Option file = new Option("file", false, "write or read to/from file");        
        options.addOption(file); 
        
        return options;
	}
}

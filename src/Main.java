import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            System.out.println("Claves generadas con éxito.");

            String mensaje = "Este es un mensaje secreto";

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] mensajeCifrado = cipher.doFinal(mensaje.getBytes());

            System.out.println("Mensaje cifrado bytes: " + Arrays.toString(mensajeCifrado));
            System.out.println("Mensaje cifrado text: " + bytesToHex(mensajeCifrado));

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] mensajeDescifrado = cipher.doFinal(mensajeCifrado);

            System.out.println("Mensaje descifrado: " + new String(mensajeDescifrado));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class jaCipher {

    public static String encrypt(String plaintext, int key, String alphabet) {
        StringBuilder encrypted = new StringBuilder();
        for (char c : plaintext.toCharArray()) {
            if (alphabet.contains(String.valueOf(c))) {
                int index = alphabet.indexOf(c);
                int shiftedIndex = (index + key) % alphabet.length();
                encrypted.append(alphabet.charAt(shiftedIndex));
            } else {
                encrypted.append(c);
            }
        }
        return encrypted.toString();
    }

    public static String decrypt(String ciphertext, int key, String alphabet) {
        int reverseKey = alphabet.length() - key;
        return encrypt(ciphertext, reverseKey, alphabet);
    }

    public static String aesEncrypt(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String aesDecrypt(String ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String customAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // Default alphabet
        SecretKey aesSecretKey = null;

        while (true) {
            System.out.println("Choose an option:");
            System.out.println("1. Encrypt a message with the regular alphabet");
            System.out.println("2. Encrypt a message with a custom alphabet");
            System.out.println("3. Decrypt a message");
            System.out.println("4. Generate Random Key and Encrypt");
            System.out.println("5. AES Encrypt a message");
            System.out.println("6. AES Decrypt a message");
            System.out.println("7. Exit");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume the newline character

            if (choice == 1) {
                // ... (as in the previous code)
                // No changes required for this option.
            } else if (choice == 2) {
                // ... (as in the previous code)
                // No changes required for this option.
            } else if (choice == 3) {
                // ... (as in the previous code)
                // No changes required for this option.
            } else if (choice == 4) {
                // ... (as in the previous code)
                // No changes required for this option.
            } else if (choice == 5) {
                try {
                    if (aesSecretKey == null) {
                        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                        keyGen.init(128); // 128-bit key size for AES
                        aesSecretKey = keyGen.generateKey();
                    }

                    System.out.print("Enter a message to AES encrypt: ");
                    String originalText = scanner.nextLine();

                    String encryptedText = aesEncrypt(originalText, aesSecretKey);
                    System.out.println("AES Encrypted: " + encryptedText);
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("AES encryption failed.");
                }
            } else if (choice == 6) {
                try {
                    if (aesSecretKey == null) {
                        System.out.println("AES secret key is not available. Please encrypt a message first.");
                    } else {
                        System.out.print("Enter an AES ciphertext to decrypt: ");
                        String encryptedText = scanner.nextLine();

                        String decryptedText = aesDecrypt(encryptedText, aesSecretKey);
                        System.out.println("AES Decrypted: " + decryptedText);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("AES decryption failed.");
                }
            } else if (choice == 7) {
                System.out.println("Exiting the program.");
                break;
            } else {
                System.out.println("Invalid choice.");
            }
        }

        scanner.close();
    }
}

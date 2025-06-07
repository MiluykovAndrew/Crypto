package example.controllers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import example.client.SendClient;
import example.model.EncryptedMessage;
import example.model.SendKey;
import example.services.EncryptionService;
import example.services.KeyService;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class MessageController {

    private final EncryptionService encryptionService;
    private final KeyService keyService;
    private final SendClient sendClien;

    private byte[] aesKey;
    private int caesarKey = 0;
    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger modulus;

    private byte[] peerAesKey;
    private int peerCaesarKey = 0;
    private BigInteger peerPublicKey;
    private BigInteger peerModulus;

    private String lastMessange;
    private String lastMethodForLastMessange;

    @PostMapping("/accept_messange")
    public void acceptMessange(@RequestBody EncryptedMessage encryptedMessage) {
        log.info("📩 Принято сообщение: {}", encryptedMessage);
        this.lastMessange = encryptedMessage.getMessage();
        this.lastMethodForLastMessange = encryptedMessage.getMethod();
        log.info("📥 Зашифрованное сообщение (при получении): {}", encryptedMessage.getMessage());
    }

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody EncryptedMessage message) throws Exception {
        log.info("🔐 Запрос на шифрование: {}", message);
        String encrypted;

        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                if (this.peerCaesarKey == 0) {
                    log.warn("❌ Caesar ключ собеседника не установлен");
                    return "У вас нет ключа собеседника";
                }
                encrypted = encryptionService.encryptCaesar(message.getMessage(), this.peerCaesarKey);
                break;

            case "aes":
                if (this.peerAesKey == null || this.peerAesKey.length == 0) {
                    log.warn("❌ AES ключ собеседника не установлен");
                    return "У вас нет ключа собеседника";
                }
                encrypted = encryptionService.aesEncrypt(message.getMessage(), this.peerAesKey);
                break;

            case "rsa":
                if (this.peerPublicKey == null || this.peerModulus == null) {
                    log.warn("❌ RSA ключ собеседника не установлен");
                    return "У вас нет ключа собеседника";
                }
                encrypted = encryptionService.rsaEncrypt(message.getMessage(), this.peerPublicKey, this.peerModulus);
                break;

            default:
                log.error("❌ Неизвестный метод шифрования: {}", message.getMethod());
                throw new IllegalArgumentException("Invalid method");
        }

        log.info("✅ Сообщение зашифровано: {}", encrypted);
        return encrypted;
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody EncryptedMessage message) throws Exception {
        log.info("🔓 Запрос на дешифровку: {}", message);
        String decrypted;
        switch (message.getMethod().toLowerCase()) {
            case "caesar":
                if (this.caesarKey == 0) {
                    log.warn("❌ Caesar ключ не установлен");
                    return "У вас нет ключа";
                }
                decrypted = encryptionService.decryptCaesar(message.getMessage(), this.caesarKey);
                break;

            case "aes":
                if (this.aesKey == null || this.aesKey.length == 0) {
                    log.warn("❌ AES ключ не установлен");
                    return "У вас нет ключа";
                }
                decrypted = encryptionService.aesDecrypt(message.getMessage(), this.aesKey);
                break;

            case "rsa":
                if (this.privateKey == null || this.modulus == null) {
                    log.warn("❌ RSA ключ не установлен");
                    return "У вас нет ключа";
                }
                decrypted = encryptionService.rsaDecrypt(message.getMessage(), this.privateKey, this.modulus);
                break;

            default:
                log.error("❌ Неизвестный метод дешифровки: {}", message.getMethod());
                throw new IllegalArgumentException("Invalid method");
        }
        log.info("✅ Сообщение расшифровано: {}", decrypted);
        return decrypted;
    }

    @PostMapping("/encrypt_and_send")
    public String encryptAndSend(@RequestBody EncryptedMessage message) throws Exception {
        log.info("📤 Шифруем и отправляем сообщение: {}", message);
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setMessage(encrypt(message));
        encryptedMessage.setMethod(message.getMethod());
        sendClien.acceptMessange(encryptedMessage);
        log.info("✅ Сообщение успешно зашифровано и отправлено: {}", encryptedMessage.getMessage());
        return "Сообщение отправлено, в зашифрованном виде оно такое: " + encryptedMessage.getMessage();
    }

    @PostMapping("/send_encrypted_msg")
    public String sendEncryptedMessage(@RequestBody EncryptedMessage message) {
        log.info("📤 Отправка зашифрованного сообщения: {}", message);
        sendClien.acceptMessange(message);
        return "Сообщение отправлено";
    }

    @GetMapping("/get_encrypted_msg")
    public String getEncryptedMessage(
            @RequestParam String method,
            @RequestParam String message
    ) throws Exception {

        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setMethod(method);
        encryptedMessage.setMessage(message);

        String decryptedMessage = decrypt(encryptedMessage);
        log.info("🔓 Расшифрованное сообщение: {}", decryptedMessage);

        return decryptedMessage;
    }

    @GetMapping("/get_encrypted_msg_last_messnge")
    public String getEncryptedLastMessenge() throws Exception {
        if (this.lastMessange == null) {
            log.error("❌ Нет последнего сообщения");
            throw new IllegalStateException("No message received.");
        }
        EncryptedMessage encryptedMessage = new EncryptedMessage();
        encryptedMessage.setMessage(this.lastMessange);
        encryptedMessage.setMethod(this.lastMethodForLastMessange);
        log.info("📥 Дешифруем последнее полученное сообщение: {}", encryptedMessage.getMessage());
        String decrypted = decrypt(encryptedMessage);
        log.info("✅ Расшифрованное сообщение: {}", decrypted);
        return decrypted;
    }



    @PostMapping("/generate")
    public String generateKeys(@RequestParam String method) throws Exception {
        log.info("⚙️ Генерация ключа для метода: {}", method);
        switch (method.toLowerCase()) {
            case "aes":
                aesKey = keyService.generateAESKey();
                String base64Key = Base64.getEncoder().encodeToString(aesKey);
                log.info("✅ AES ключ успешно сгенерирован: {}", base64Key);
                return "AES ключ сгенерирован: " + base64Key;

            case "rsa":
                generateRSAKeys();
                return "RSA ключ сгенерирован";

            case "caesar":
                Random random = new Random();
                caesarKey = random.nextInt(100) + 1; // ключ не 0
                log.info("✅ Caesar ключ сгенерирован: {}", caesarKey);
                return "Caesar ключ сгенерирован: " + caesarKey;

            default:
                log.error("❌ Неизвестный метод генерации ключа: {}", method);
                throw new IllegalArgumentException("Invalid method");
        }
    }


    @PostMapping("/send_public_key")
    public void sendPublicKey(@RequestParam String method) {
        log.info("📤 Отправка публичного ключа: {}", method);
        SendKey encryptedMessage = new SendKey();
        encryptedMessage.setMethod(method);

        switch (method.toLowerCase()) {
            case "rsa":
                encryptedMessage.setA(publicKey);
                encryptedMessage.setM(modulus);
                log.info("🔑 Отправка RSA Public Key: e = {}, n = {}", publicKey.toString(16), modulus.toString(16));
                break;
            case "aes":
                encryptedMessage.setKey(this.aesKey);
                log.info("🔑 Отправка AES ключа (Base64): {}", Base64.getEncoder().encodeToString(this.aesKey));
                break;
            case "caesar":
                encryptedMessage.setC(this.caesarKey);
                log.info("🔑 Отправка Caesar ключа: {}", this.caesarKey);
                break;
            default:
                log.warn("❌ Неизвестный метод отправки ключа: {}", method);
                return;
        }

        sendClien.getPublicKey(encryptedMessage);
        log.info("✅ Ключ отправлен успешно");
    }

    @PostMapping("/get_public_key")
    public void getPublicKey(@RequestBody SendKey encryptedMessage) {
        log.info("📥 Получение публичного ключа: {}", encryptedMessage.getMethod());
        switch (encryptedMessage.getMethod().toLowerCase()) {
            case "rsa":
                this.peerPublicKey = encryptedMessage.getA();
                this.peerModulus = encryptedMessage.getM();
                log.info("🔓 Получен RSA Public Key собеседника: e = {}, n = {}", peerPublicKey.toString(16), peerModulus.toString(16));
                break;
            case "aes":
                this.peerAesKey = encryptedMessage.getKey();
                log.info("🔓 Получен AES ключ собеседника (Base64): {}", Base64.getEncoder().encodeToString(peerAesKey));
                break;
            case "caesar":
                this.peerCaesarKey = encryptedMessage.getC();
                log.info("🔓 Получен Caesar ключ собеседника: {}", peerCaesarKey);
                break;
            default:
                log.warn("❌ Неизвестный метод получения ключа: {}", encryptedMessage.getMethod());
        }
    }


    private void generateRSAKeys() {
        log.info("⚙️ Генерация RSA ключей...");
        SecureRandom random = new SecureRandom();
        int bitLength = 1024;

        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        modulus = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        do {
            publicKey = new BigInteger(bitLength / 2, random);
        } while (!phi.gcd(publicKey).equals(BigInteger.ONE) || publicKey.compareTo(BigInteger.ONE) <= 0 || publicKey.compareTo(phi) >= 0);

        privateKey = publicKey.modInverse(phi);

        log.info("✅ RSA ключи сгенерированы");
        log.info("🔑 Public Key (e): {}", publicKey.toString(16));
        log.info("🔐 Private Key (d): {}", privateKey.toString(16));
    }
}

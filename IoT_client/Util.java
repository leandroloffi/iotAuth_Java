
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ************** UTIL **************
 */
public class Util {

    /*public String read(File file){
        String dados = "";
        try{
            FileReader fileReader = new FileReader(file);
            BufferedReader reader = new BufferedReader(fileReader);
            String data = null;
            while((data = reader.readLine()) != null){
                dados += data;
            }
            fileReader.close();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return dados;
    }*/



    public void write_data_txt(ArrayList<String> dados, String arquivo){
        String pathname = "d:\\planilhas_valores_IoT\\Client\\" +arquivo+ ".txt";
        String data = "";
        /*File file = new File(pathname);
        if(file.exists()){
           data = read(file);
        }*/
        try {

            FileWriter arq = new FileWriter(pathname);
            PrintWriter gravarArq = new PrintWriter(arq);

            String aux = "";
            for (int i = 0; i < dados.size(); i++){
                aux = aux + dados.get(i) + "\n";
            }

            if(!data.equals("")){
                gravarArq.printf(data + aux);
            }else{
                gravarArq.printf(aux);
            }

            arq.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    String encryption_ECIES(PublicKey publicKey, String data){
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher iesCipher = Cipher.getInstance("ECIES");
            iesCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] ciphertext = iesCipher.doFinal(data.getBytes());
            return Base64b_S(ciphertext);

        }catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    String decryption_ECIES(PrivateKey privateKey, String data){
        try {
            byte[] entrada = Base64S_b(data);
            Security.addProvider(new BouncyCastleProvider());
            Cipher iesCipher = Cipher.getInstance("ECIES");
            iesCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] ciphertext = iesCipher.doFinal(entrada);
            return new String (ciphertext);

        }catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    String getNonce(String ipDest, String ipSource, int seq, String algoritmo) {
        String valores = System.currentTimeMillis() + "|" + ipDest + "|" + ipSource + "|" + seq;
        SHA sha = new SHA(algoritmo);
        return sha.getSHA(valores);
    }

    String Base64b_S(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    byte[] Base64S_b(String string) {
        return Base64.getDecoder().decode(string);
    }

    public ArrayList<Letters> get_letters() {

        ArrayList<Letters> lista = new ArrayList<>();

        // Loop over all possible ASCII codes.
        int min = 0;
        int max = 128;
        for (int i = min; i < max; i++) {
            char c = (char) i;
            String display = "";
            // Figure out how to display whitespace.
            if (Character.isWhitespace(c)) {
                switch (c) {
                    case '\t':
                        display = "\\t";
                        break;
                    case ' ':
                        display = "space";
                        break;
                    case '\n':
                        display = "\\n";
                        break;
                    case '\r':
                        display = "\\r";
                        break;
                    case '\f':
                        display = "\\f";
                        break;
                    default:
                        display = "whitespace";
                        break;
                }
            } else if (Character.isISOControl(c)) {
                // Handle control chars.
                display = "control";
            } else {
                // Handle other chars.
                display = Character.toString(c);
            }
            // Write a string with padding.
            lista.add(new Letters(i, display, Integer.toHexString(i)));
        }
        return lista;
    }

    long response_Fdr(FDR Fdr, char[] asciiValue) {
        ArrayList<Letters> letras_numeros = get_letters();
        int soma_Kpub = 0;
        for (int i = 0; i < asciiValue.length; i++) {
            for (int j = 0; j < letras_numeros.size(); j++) {
                String t = Character.toString(asciiValue[i]);
                if (t.equals(letras_numeros.get(j).letter)) {
                    soma_Kpub = soma_Kpub + letras_numeros.get(j).integer;
                }
            }
        }
        return Fdr.response_Fdr_internal(soma_Kpub);
    }

}

class Letters {

    int integer;
    String letter;
    String hexa;

    Letters(int inteiro, String letter, String hexa) {
        this.integer = inteiro;
        this.letter = letter;
        this.hexa = hexa;
    }
}

class ECDHE {
    Key_elliptical_curve kp_B;
    Key_elliptical_curve kp_A;
    private byte[] sharedSecret;
    ECDHE(){
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            this.kp_A = new Key_elliptical_curve(kpg.generateKeyPair());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    public void set_Kp_B(String publicKey_S){
        kp_B = new Key_elliptical_curve(publicKey_S);
    }

    public void setSharedSecret(PublicKey publicKey) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp_A.getPrivateKey());
            ka.doPhase(publicKey, true);
            // Read shared secret
            this.sharedSecret = ka.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}

class STEPS_data_client {

    ArrayList<String> time_values;
    ECDHE ecdhe;
    values_DH dh;
    byte[] key_session;
    String iv_AES;
    Keys_RSA keys_rsa_A;
    Keys_RSA keys_rsa_B;
    Key_elliptical_curve keys_ecc_A;
    Key_elliptical_curve keys_ecc_B;
    FDR Fdr_A;
    FDR Fdr_B;
    long tp_A;
    long tp_B;
    long time_network;
    UDPClient udp;
    String ipDest;
    String ipSource;
    String algorithmSHA;
    String nonce_A;
    String nonce_B;
    int seqNumber;
    String data;
    String erro;

    STEPS_data_client(long time_network, UDPClient udp, String ipDest,
                      String ipSource, String algoritmoSHA, String nonce_A,
                      int seqNumber, String tempo_resultado) {
        this.ecdhe = null;
        this.dh = null;
        this.keys_rsa_A = null;
        this.keys_rsa_B = null;
        this.keys_ecc_A = null;
        this.keys_ecc_B = null;
        this.Fdr_A = null;
        this.Fdr_B = null;
        this.tp_A = 0;
        this.tp_B = 0;
        this.time_network = time_network;
        this.udp = udp;
        this.ipDest = ipDest;
        this.ipSource = ipSource;
        this.algorithmSHA = algoritmoSHA;
        this.nonce_A = nonce_A;
        this.nonce_B = "";
        this.key_session = null;
        this.iv_AES = "";
        this.seqNumber = seqNumber;
        this.data = "";
        this.erro = "";
        this.time_values = new ArrayList<>();
        this.time_values.add(tempo_resultado);
    }
}


/**
 * ************** AES **************
 */
class AES {

    private final String characterEncoding = "UTF-8";
    private final String cipherTransformation;
    private final String aesEncryptionAlgorithm;
    Util util = new Util();

    public AES(String modo, String Padding) {
        cipherTransformation = "AES/" + modo + "/" + Padding;
        aesEncryptionAlgorithm = "AES";
    }

    public AES() {
        cipherTransformation = "AES/CBC/PKCS5Padding";
        aesEncryptionAlgorithm = "AES";
    }

    public byte[] decrypt_AES1(byte[] cipherText, byte[] key, byte[] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpecy = new SecretKeySpec(key, aesEncryptionAlgorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpecy, ivParameterSpec);
        cipherText = cipher.doFinal(cipherText);
        return cipherText;
    }

    public byte[] encrypt_AES1(byte[] plainText, byte[] key, byte[] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, aesEncryptionAlgorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        plainText = cipher.doFinal(plainText);
        return plainText;
    }

    private byte[] getKeyBytes(String key, int tam_key) throws UnsupportedEncodingException {
        byte[] keyBytes = new byte[tam_key];
        byte[] parameterKeyBytes = key.getBytes(characterEncoding);
        System.arraycopy(parameterKeyBytes, 0, keyBytes, 0, Math.min(parameterKeyBytes.length, keyBytes.length));
        return keyBytes;
    }

    public String encrypt_AES(String plainText, String key, int tam_key, String iv) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] plainTextbytes = plainText.getBytes(characterEncoding);
        byte[] keyBytes = getKeyBytes(key, tam_key);
        byte[] ivBytes = getKeyBytes(iv, tam_key);
        return util.Base64b_S(encrypt_AES1(plainTextbytes, keyBytes, ivBytes));
    }

    public String decrypt_AES(String encryptedText, String key, int tam_key, String iv) throws KeyException, GeneralSecurityException, GeneralSecurityException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] cipheredBytes = util.Base64S_b(encryptedText);
        byte[] keyBytes = getKeyBytes(key, tam_key);
        byte[] ivBytes = getKeyBytes(iv, tam_key);
        return new String(decrypt_AES1(cipheredBytes, keyBytes, ivBytes), characterEncoding);
    }
}

final class Key_elliptical_curve {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    Key_elliptical_curve(KeyPair pair){
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    Key_elliptical_curve(){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    Key_elliptical_curve(String publicKey_S){
        Util util = new Util();
        byte[] publicBytes1 = util.Base64S_b(publicKey_S);
        try {

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes1);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    Key_elliptical_curve(PublicKey publicKey){
        this.publicKey = publicKey;
    }

    Key_elliptical_curve(PublicKey publicKey, PrivateKey privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}

final class Keys_ECC{
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String publicKey_S;
    private String privateKey_S;
    private Util util = new Util();

    Keys_ECC() throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");

        keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());

        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
        publicKey_S = util.Base64b_S(publicKey.getEncoded());
        privateKey_S = util.Base64b_S(privateKey.getEncoded());
    }

    Keys_ECC(String publicKey_S, String privateKey_S) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKey_b = util.Base64S_b(publicKey_S);
        byte[] privateKey_b = util.Base64S_b(privateKey_S);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey_b);
        privateKey = keyFactory.generatePrivate(privateKeySpec);
        this.privateKey_S = privateKey_S;

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey_b);
        publicKey = keyFactory.generatePublic(publicKeySpec);
        this.publicKey_S = publicKey_S;
    }

    Keys_ECC(String publicKey_S) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] publicBytes = util.Base64S_b(publicKey_S);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        publicKey = keyFactory.generatePublic(keySpec);
        this.publicKey_S = publicKey_S;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey_S() {
        return privateKey_S;
    }

    public String getPublicKey_S() {
        return publicKey_S;
    }
}

/**
 * ************** KEYS RSA **************
 */
final class Keys_RSA {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String publicKey_S;
    private String privateKey_S;
    Util util = new Util();

    Keys_RSA(String publicKey_S, String privateKey_S, String rsaEncryptionAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKey_b = util.Base64S_b(publicKey_S);
        byte[] privateKey_b = util.Base64S_b(privateKey_S);
        KeyFactory keyFactory = KeyFactory.getInstance(rsaEncryptionAlgorithm);

        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey_b);
        privateKey = keyFactory.generatePrivate(privateKeySpec);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey_b);
        publicKey = keyFactory.generatePublic(publicKeySpec);

        this.publicKey_S = util.Base64b_S(publicKey.getEncoded());
        this.privateKey_S = util.Base64b_S(privateKey.getEncoded());
    }

    Keys_RSA(String publicKey_S, String rsaEncryptionAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] publicBytes = util.Base64S_b(publicKey_S);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(rsaEncryptionAlgorithm);
        publicKey = keyFactory.generatePublic(keySpec);
        this.publicKey_S = publicKey_S;
    }

    Keys_RSA(String rsaEncryptionAlgorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPair keyPair = buildKeyPair(rsaEncryptionAlgorithm, keySize);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        publicKey_S = util.Base64b_S(keyPair.getPublic().getEncoded());
        privateKey_S = util.Base64b_S(keyPair.getPrivate().getEncoded());
    }

    private KeyPair buildKeyPair(String rsaEncryptionAlgorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(rsaEncryptionAlgorithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey_S() {
        return privateKey_S;
    }

    public String getPublicKey_S() {
        return publicKey_S;
    }
}

/**
 * ************** RSA **************
 */
class RSA {

    private final String rsaEncryptionAlgorithm;
    private Util util = new Util();

    RSA(String rsaEncryptionAlgorithm) {
        this.rsaEncryptionAlgorithm = rsaEncryptionAlgorithm;
    }

    public String encrypt_RSA_A(PrivateKey privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(rsaEncryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return util.Base64b_S(cipher.doFinal(message.getBytes()));
    }

    public String encrypt_RSA_E(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance(rsaEncryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return util.Base64b_S(cipher.doFinal(message.getBytes()));
    }

    public String decrypt_RSA_A(PublicKey publicKey, String encrypted) throws Exception {
        byte[] cipheredBytes = util.Base64S_b(encrypted);
        Cipher cipher = Cipher.getInstance(rsaEncryptionAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(cipher.doFinal(cipheredBytes));
    }

    public String decrypt_RSA_E(PrivateKey privateKey, String encrypted) throws Exception {
        byte[] cipheredBytes = util.Base64S_b(encrypted);
        Cipher cipher = Cipher.getInstance(rsaEncryptionAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(cipheredBytes));
    }

}

/**
 * ************** SHA **************
 */
class SHA {

    private String algorithm_sha;

    SHA(String algorithm_sha) {
        this.algorithm_sha = algorithm_sha;
    }

    private static final char[] hexArray = "0123456789abcdef".toCharArray();

    public String getSHA(String data) {
        StringBuilder sb = new StringBuilder();
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm_sha);
            md.update(data.getBytes());
            byte[] byteData = md.digest();
            sb.append(bytesToHex(byteData));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sb.toString();
    }

    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return String.valueOf(hexChars);
    }
}



class UDPClient {

    private DatagramSocket clientSocket;
    private InetAddress IPAddress;
    private int port;
    private String server;

    public UDPClient(String server, int port) throws SocketException, UnknownHostException {
        clientSocket = new DatagramSocket();
        this.port = port;
        this.server = server;
        IPAddress = InetAddress.getByName(server);
    }

    public void SendUDPclient(String sentence) throws Exception {
        byte[] sendData = new byte[2048];
        sendData = sentence.getBytes();
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, port);

        //System.out.println("Enviando pacote UDP para " + servidor + ":" + porta);
        clientSocket.send(sendPacket);

    }

    public String receiveUDPclient(int timeout) throws Exception {
        byte[] receiveData = new byte[4096];

        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
        clientSocket.setSoTimeout(timeout);

        try {
            clientSocket.receive(receivePacket);
        } catch (SocketTimeoutException e) {
            // resend
            return "timeOut";
        }

        return (new String(receivePacket.getData()));
    }

    public String receiveUDPclient() throws Exception {
        byte[] receiveData = new byte[4096];

        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        clientSocket.receive(receivePacket);

        return (new String(receivePacket.getData()));
    }

    public void closeUDP() {
        clientSocket.close();
        System.out.println("\nSocket cliente fechado!");
    }
}

class FDR {

    private String operation_choice[] = {"+", "-", "*"};
    String operation;
    long value;

    FDR(int tamanho) {
        Random r = new Random();
        int op_gerado = r.nextInt(tamanho) % 3;
        value = r.nextInt(tamanho);
        operation = operation_choice[op_gerado];
    }

    FDR(String operation, long value) {
        this.value = value;
        this.operation = operation;
    }

    public long response_Fdr_internal(long value_ent) {
        if (operation.equals("+")) {
            value = value + value_ent;
        } else if (operation.equals("-")) {
            value = value - value_ent;
        } else if (operation.equals("*")) {
            value = value * value_ent;
        }
        return value;
    }

}

class values_DH {

    BigInteger P;
    BigInteger G;
    byte[] myPublicKey;

    public values_DH(BigInteger P, BigInteger G, byte[] myPublicKey) {
        this.P = P;
        this.G = G;
        this.myPublicKey = myPublicKey;
    }
}

class DH {

    private static byte P_BYTES[];
    private static byte G_BYTES[];

    private KeyPair keyPair;
    private KeyAgreement keyAgree;

    public values_DH generatePublicKey(values_DH values, int ARRAY_LENGTH, boolean verbose) {
        DHParameterSpec dhParamSpec;

        try {
            dhParamSpec = new DHParameterSpec(P, G);
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGen.initialize(dhParamSpec);
            keyPair = keyPairGen.generateKeyPair();
            if (verbose) {
                System.out.println("Y = " + ((DHPublicKey) keyPair.getPublic()).getY().toString(16));
            }
            keyAgree = KeyAgreement.getInstance("DiffieHellman");
            keyAgree.init(keyPair.getPrivate());

            BigInteger pubKeyBI = ((DHPublicKey) keyPair.getPublic()).getY();
            byte[] pubKeyBytes = pubKeyBI.toByteArray();
            values = new values_DH(P, G, pubKeyBytes);
            return values;
        } catch (Exception e) {
            //System.out.println("ERRO: DH - generatePubKey(): " + e.getMessage());
            generate_P_G(ARRAY_LENGTH);
            return generatePublicKey(values, ARRAY_LENGTH, verbose);
        }
    }

    public byte[] computeSharedKey(byte[] pubKeyBytes) {
        if (keyAgree == null) {
            System.out.println("ERRO: DH - computeSharedKey(): keyAgree IS NULL!!");
            return null;
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            BigInteger pubKeyBI = new BigInteger(1, pubKeyBytes);
            //System.out.println("Y = " + pubKeyBI.toString(16));
            PublicKey pubKey = keyFactory.generatePublic(new DHPublicKeySpec(pubKeyBI, P, G));
            keyAgree.doPhase(pubKey, true);
            byte[] sharedKeyBytes = keyAgree.generateSecret();
            return sharedKeyBytes;
        } catch (Exception e) {
            System.out.println("ERRO: DH - computeSharedKey(): " + e.getMessage());
            return null;
        }
    }

    public void generate_P_G(int ARRAY_LENGTH) {

        SecureRandom random = new SecureRandom();
        P_BYTES = new byte[ARRAY_LENGTH];
        G_BYTES = new byte[ARRAY_LENGTH];
        random.nextBytes(P_BYTES);
        random.nextBytes(G_BYTES);

        // get fisrt element
        P = new BigInteger(1, P_BYTES);
        G = new BigInteger(1, G_BYTES);
    }

    public void Set_P_G(BigInteger P, BigInteger G) {
        this.P = P;
        this.G = G;
    }

    private static BigInteger P;

    private static BigInteger G;
}

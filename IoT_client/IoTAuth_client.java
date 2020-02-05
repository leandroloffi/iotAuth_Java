
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Leandro Loffi
 * @date 29/11/2018
 */
public class IoTAuth_client {

    private Util_client util;
    private UDPClient udp;
    private String key_session;
    private int key_size_AES = 16;
    private String iv_AES;
    private boolean is_connected;
    private boolean is_problem = false;
    private String delimiter = ";";
    private boolean verbose;

    public IoTAuth_client(boolean verbose) {
        util = new Util_client(verbose);
        this.verbose = verbose;
    }

    public boolean connect(String address, int port) {
        is_connected = false;

        System.out.println("\n:::: CLIENTE ::::\nCONNECT PORT: " + port);

        try {
            String retorno = "";
            udp = new UDPClient(address, port);
            udp.SendUDPclient("connect;");
            retorno = udp.receiveUDPclient(5000);
            String[] valores = retorno.split(";");
            if (verbose) {
                System.out.println("data: " + retorno);
            }
            if(retorno.equals("timeOut")){
                is_problem = false;
            }
            if (valores[0].equals("ok")) {
                long tempo = System.currentTimeMillis();


                String ciphersuite = valores[1];
                if(!ciphersuite.equals("DH_RSA_AES128-CBC_SHA512") && !ciphersuite.equals("ECDHE_ECDSA_AES128-CBC_SHA512")){
                    System.out.println("CipherSuite not suport!");
                    return false;
                }
                //String ciphersuite_ECC = "ECDHE_ECDSA_AES128-CBC_SHA512";

                /*
                1º Troca de chaves
                2º Cifragem assimetrica
                3º Cifragem simetrica
                4º Hash de autenticação

                DH_RSA_AES128-CBC_SHA512
                DH_RSA_AES256-CBC_SHA512
                ECDHE_ECDSA_AES128-CBC_SHA512
                ECDHE_ECDSA_AES256-GCM_SHA384
                ECDHE_RSA_AES256-GCM_SHA384
                ECDHE_ECDSA_CHACHA20_POLY1305
                ECDHE_RSA_CHACHA20_POLY1305
                ECDHE_ECDSA_AES128-GCM_SHA256
                ECDHE_RSA_AES128-GCM_SHA256
                ECDHE_ECDSA_AES256_SHA384
                ECDHE_RSA_AES256_SHA384
                ECDHE_ECDSA_AES128_SHA256
                ECDHE_RSA_AES128_SHA256
                * */

                boolean t = handshake(ciphersuite, address, port);
                tempo = System.currentTimeMillis() - tempo;
                System.out.println("\nTEMPO: " + tempo);
                if(t == false){
                    is_problem = true;
                }
                return t;
            }
        } catch (SocketException | UnknownHostException ex) {
            System.out.println("ERRO try catch: " + ex.getMessage());
        } catch (Exception ex) {
            System.out.println("ERRO try catch: " + ex.getMessage());
        }
        return false;
    }

    public boolean isConnected() {
        return is_connected;
    }

    private boolean isProblem(){
        return is_problem;
    }

    public boolean publish(String data) {
        return publish_client(data, 0);
    }

    public boolean publish(String data, int timeout) {
        return publish_client(data, timeout);
    }

    private boolean publish_client(String data, int timeout) {
        if (data.equals("done")) {
            disconnect();
            return false;
        }
        if (isConnected()) {

            try {
                util.step_9_client_send(key_session, key_size_AES, iv_AES, udp, data);
                String recebido = util.step_9_client_received(key_session, key_size_AES, iv_AES, udp, timeout);

                if (recebido.equals("ok")) {
                    return true;
                } else {
                    System.out.println(">>> " + recebido);
                }
            } catch (Exception ex) {
                System.out.println("ERRO try catch: " + ex.getMessage());
            }
        }
        return false;
    }

    public String request(String data, int timeout) {
        return request_client(data, timeout);
    }

    public String request(String data) {
        return request_client(data, 0);
    }

    public String request(int timeout) {
        return request_client("", timeout);
    }

    public String request() {
        return request_client("", 0);
    }

    private String request_client(String data, int timeout) {
        if (isConnected()) {
            if (data.equals("")) {
                data = "request;";
            } else {
                data = "request;" + data + ";";
            }
            if (verbose) {
                System.out.println("DATA: " + data);
            }
            try {
                util.step_9_client_send(key_session, key_size_AES, iv_AES,  udp, data);
                String recebido = util.step_9_client_received(key_session, key_size_AES, iv_AES, udp, timeout);
                if (recebido.equals("done")) {
                    return "DESCONECTADO";
                }
                util.step_9_client_send(key_session, key_size_AES, iv_AES,  udp, "ok");
                return recebido;
            } catch (Exception ex) {
                System.out.println("ERRO try catch: " + ex.getMessage());
                is_problem = true;
            }
        }
        return "";
    }

    public boolean disconnect(int timeout) {
        return disconnect_client(timeout);
    }

    public boolean disconnect() {
        return disconnect_client(0);
    }

    private boolean disconnect_client(int timeout) {
        if (isConnected()) {
            try {
                util.step_9_client_send(key_session, key_size_AES, iv_AES, udp, "done");
                String recebido = util.step_9_client_received(key_session, key_size_AES, iv_AES, udp, timeout);
                if (recebido.equals("ok")) {
                    is_connected = false;
                    return true;
                } else if (recebido.equals("timeout")) {
                    is_connected = false;
                    is_problem = true;
                    return true;
                }
            } catch (Exception ex) {
                System.out.println("ERRO try catch: " + ex.getMessage());
                is_problem = true;
            }
        }
        return false;
    }

    public boolean handshake(String ciphersuite, String IP, int porta) {
        try {
            try {
                try {
                    udp = new UDPClient(IP, porta);
                    if (verbose) {
                        System.out.println("******** HANDSHAKE CLIENT ********");
                    }
                    // DH_RSA_AES256-CBC_SHA512
                    // ECDHE_ECDSA_AES128-CBC_SHA512
                    String[] algoritmos = ciphersuite.split("_");

                    String algoritmo_SHA = "";
                    boolean algoritmo_DH_RSA = false;
                    boolean algoritmo_ECDHE_ECDSA = false;
                    boolean algoritmo_ECDHE_RSA = false;
                    int tam_chave_RSA = 2048;
                    int tam_ger_dh = 64;
                    String modo_AES = "";
                    String modo_padding = "PKCS5Padding";

                    /******************* TAXA DE ERRO (ACEITAÇÃO)********************/
                    double taxa_tempo = 0.5;
                    /****************************************************************/

                    if(algoritmos[0].equals("DH")){
                        if(algoritmos[1].equals("RSA")) {
                            algoritmo_DH_RSA = true;
                        }else{
                            System.out.println("ERRO NÃO HÁ CIPHER SUPORTADA: " + algoritmos[0] + "<<>> " + algoritmos[1]);
                            return false;
                        }
                    }else if(algoritmos[0].equals("ECDHE")){
                        if(algoritmos[1].equals("ECDSA")) {
                            algoritmo_ECDHE_ECDSA = true;
                        }else if(algoritmos[1].equals("RSA")){
                            algoritmo_ECDHE_RSA = true;
                        }else{
                            System.out.println("ERRO NÃO HÁ CIPHER SUPORTADA: " + algoritmos[0] + "<<>> " + algoritmos[1]);
                            return false;
                        }
                    }else{
                        System.out.println("ERRO NÃO HÁ CIPHER SUPORTADA >> " + algoritmos[0]);
                        return false;
                    }

                    // 3ª PARTE
                    if(algoritmos[2].equals("AES256-CBC")){
                        modo_AES = "CBC";
                        key_size_AES = 32;
                    }else if(algoritmos[2].equals("AES192-CBC")){
                        modo_AES = "CBC";
                        key_size_AES = 24;
                    }else if(algoritmos[2].equals("AES128-CBC")){
                        modo_AES = "CBC";
                        key_size_AES = 16;
                    }else if(algoritmos[2].equals("AES128-GCM")){
                        modo_AES = "GCM";
                        key_size_AES = 16;
                    }else{
                        System.out.println("Não foi configurado o algoritmo: " + algoritmos[2]);
                        return false;
                    }

                    if(algoritmos[3].equals("SHA512")){
                        algoritmo_SHA = "SHA-512";
                    }else if(algoritmos[3].equals("SHA384")){
                        algoritmo_SHA = "SHA-384";
                    }else if(algoritmos[3].equals("SHA256")){
                        algoritmo_SHA = "SHA-256";
                    }else if(algoritmos[3].equals("SHA224")){
                        algoritmo_SHA = "SHA-224";
                    }else{
                        System.out.println("Não foi configurado o algoritmo: " + algoritmos[3]);
                        return false;
                    }

                    if (verbose) {
                        System.out.println("\n******** STEP 1 ********\nPacket send");
                        System.out.println("C->S: Syn, nA");
                    }
                    STEPS_data_client data = util.step_1_client(udp, IP, InetAddress.getLocalHost().getHostAddress(), algoritmo_SHA);

                    if (data.erro.equals("")) {

                        if (verbose) {
                            System.out.println("\n******** STEP 2 ********\nPacket received");
                            System.out.println("S->C: Ack, nA, nB");
                        }
                        data = util.step_2_client(data);

                        if (data.erro.equals("")) {

                            if (verbose) {
                                System.out.println("\n******** STEP 3 ********\nPacket send");
                                System.out.println("C->S: {KApub FdrA, nB, nA} Ass, tpA");
                            }
                            if(algoritmo_ECDHE_ECDSA) {
                                data = util.steps_3_client_EC(data, algoritmo_SHA, 10000);
                            }else if(algoritmo_ECDHE_RSA || algoritmo_DH_RSA){
                                data = util.step_3_client_RSA(data, delimiter, tam_chave_RSA, algoritmo_SHA, 10000);
                            }else{
                                return false;
                            }

                            if (data.erro.equals("")) {
                                if (verbose) {
                                    System.out.println("\n******** STEP 4 ********\nPacket received");
                                    System.out.println("S->C: {KBpub, F(KApub), FdrB, nA, nB} Ass, tpB");
                                }

                                if(algoritmo_ECDHE_ECDSA) {
                                    data = util.step_4_client_EC(data, taxa_tempo, algoritmo_SHA);
                                }else if(algoritmo_ECDHE_RSA || algoritmo_DH_RSA){
                                    data = util.step_4_client_RSA(data, taxa_tempo, delimiter, algoritmo_SHA);
                                }else{
                                    return false;
                                }
                                if (data.erro.equals("")) {
                                    if (verbose) {
                                        System.out.println("\n******** STEP 5 ********\nPacket send");
                                        System.out.println("C->S: {Ack, F(KBpub), nB, nA} Ass");
                                    }
                                    if(algoritmo_ECDHE_ECDSA) {
                                        data = util.step_5_client_EC(data, algoritmo_SHA);
                                    }else if(algoritmo_ECDHE_RSA || algoritmo_DH_RSA){
                                        data = util.step_5_client_RSA(data, delimiter, algoritmo_SHA);
                                    }else{
                                        return false;
                                    }
                                    if (data.erro.equals("")) {
                                        if (verbose) {
                                            System.out.println("\n******** STEP 6 ********\nPacket received");
                                            System.out.println("S->C: {{DHB, g, p, iv, nA, nB} Ass} Cif, tpB");
                                        }
                                        if(algoritmo_ECDHE_RSA || algoritmo_ECDHE_ECDSA) {
                                            data = util.step_6_client_EC(data, algoritmo_SHA, 5000);
                                        }else if(algoritmo_DH_RSA){
                                            data = util.step_6_client_RSA(data, delimiter, algoritmo_SHA, 5000);
                                        }else{
                                            return false;
                                        }
                                        if (data.erro.equals("")) {
                                            if (verbose) {
                                                System.out.println("\n******** STEP 7 ********\nPacket send");
                                                System.out.println("C->S: {{DHA, nB, nA} Ass} Cif, tpA");
                                            }
                                            if(algoritmo_ECDHE_RSA || algoritmo_ECDHE_ECDSA) {
                                                data = util.step_7_client_EC(data, algoritmo_SHA, 5000);
                                            }else if(algoritmo_DH_RSA){
                                                data = util.step_7_client_RSA(data, tam_ger_dh, delimiter, algoritmo_SHA, 5000);
                                            }else {
                                                return false;
                                            }
                                            if (data.erro.equals("")) {
                                                if (verbose) {
                                                    System.out.println("\n******** STEP 8 ********\nPacket received");
                                                    System.out.println("S->C: {Ack, nA}DHk");
                                                }
                                                if(algoritmo_ECDHE_RSA || algoritmo_ECDHE_ECDSA) {
                                                    key_session = util.step_8_client_EC(data, modo_AES, modo_padding, 16, taxa_tempo, porta);

                                                }else if(algoritmo_DH_RSA){
                                                    key_session = util.step_8_client_RSA(data, delimiter, modo_AES, modo_padding, 16, taxa_tempo, porta);
                                                }else {
                                                    return false;
                                                }

                                                if(key_session == null){
                                                    data.erro = "ERRO: key session = null";
                                                }

                                                iv_AES = data.iv_AES;
                                                if (key_session != null) {
                                                    is_connected = true;
                                                    return true;
                                                } else {
                                                    System.out.println("HANDSHAKE TERMINOU COM ERRO!");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (!data.erro.equals("")) {
                        System.out.println("HANDSHAKE TERMINOU COM ERRO!");
                        System.out.println(data.erro);
                    }
                    udp.closeUDP();
                } catch (UnsupportedEncodingException
                        | InvalidKeyException
                        | NoSuchAlgorithmException
                        | NoSuchPaddingException
                        | InvalidAlgorithmParameterException
                        | IllegalBlockSizeException
                        | BadPaddingException ex) {
                    System.out.println("ERRO Try catch: " + ex.getMessage());
                }
            } catch (GeneralSecurityException
                    | IOException ex) {
                System.out.println("ERRO Try catch: " + ex.getMessage());
            }
        } catch (Exception ex) {
            System.out.println("ERRO Try catch: " + ex.getMessage());
        }
        return false;
    }

}

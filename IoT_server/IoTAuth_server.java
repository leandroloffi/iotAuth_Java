
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Leandro Loffi
 */
/*
class nos_sensor {

    DatagramPacket data;
    boolean connected;

    nos_sensor(DatagramPacket data, boolean status) {
        this.data = data;
        connected = status;
    }
}*/
public class IoTAuth_server {

    private UDPserver udp_server;
    private String delimiter = ";";
    private String key_session;
    private int key_size_AES = 16;
    private String iv_AES;
    private Util_server util;
    private boolean is_connected = false;
    private String publish_server = "";
    private DatagramPacket data = null;
    private boolean verbose;
    private String ciphersuite = "DH_RSA_AES128-CBC_SHA512";
    private String IP;
    private int port;
    //private ArrayList<nos_sensor> connected = new ArrayList<>();

    IoTAuth_server(boolean verbose) {
        this.verbose = verbose;
        util = new Util_server(verbose);
    }

    public boolean wait_connect(int port) {
        return wait_connect_server(port, 0);
    }

    /*public boolean is_Connected(String IP, int Port) {
        for (int i = 0; i < connected.size(); i++) {
            if (connected.get(i).data.getAddress().getHostAddress().equals(IP)
                    && connected.get(i).data.getPort() == Port) {
                System.out.println("ENTROU!");
                return connected.get(i).connected;
            }
        }
        return false;
    }*/
    public boolean wait_connect(int port, int timeOut) {
        return wait_connect_server(port, timeOut);
    }

    public boolean setciphersuite(String ciphersuite){
        if(ciphersuite.equals("DH_RSA_AES128-CBC_SHA512") || ciphersuite.equals("ECDHE_ECDSA_AES128-CBC_SHA512")){
            this.ciphersuite = ciphersuite;
            return true;
        }else{
            System.out.println(">> " + ciphersuite + " - Write Incorrect -  Not Support");
        }
        return false;
    }

    public String getIP() {
        return IP;
    }

    public int getPort() {
        return port;
    }

    private boolean wait_connect_server(int port, int timeOut) {
        System.out.println("\n:::: SERVIDOR ::::\nESCUTANDO PORTA: " + port);
        DatagramPacket retorno = null;

        try {
            do {
                udp_server = new UDPserver(port);
                if (timeOut == 0) {
                    retorno = udp_server.receiveUDPserver();
                } else {
                    retorno = udp_server.receiveUDPserver(timeOut);
                }
            } while (retorno == null);
            IP = retorno.getAddress().getHostAddress();
            port = retorno.getPort();
        } catch (SocketException ex) {
            System.out.println("ERRO try catch: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("ERRO try catch: " + ex.getMessage());
        }

        String valor = new String(retorno.getData());
        if (verbose) {
            System.out.println("RETORNO: " + valor);
        }
        if (!valor.equals("timeOut")) {
            String[] valores = valor.split(";");
            if (verbose) {
                System.out.println("IP dest: " + retorno.getAddress().getHostAddress() + " : " + retorno.getPort());
            }
            if (valores[0].equals("connect")) {
                try {
                    udp_server.sendUDPserver("ok;" + ciphersuite + ";", retorno.getAddress(), retorno.getPort());
                    if (handshake(ciphersuite, retorno.getAddress().getHostAddress(), port) == true) {
                        is_connected = true;
                        return true;
                    }
                } catch (Exception ex) {
                    System.out.println("ERRO try catch: " + ex.getMessage());
                }
            }
        }
        return false;
    }

    public boolean is_connected() {
        return is_connected;
    }

    public String listen() throws GeneralSecurityException, Exception {
        return listen_server(0);
    }

    public String listen(int timeout)  {
        return listen_server(timeout);
    }

    private String listen_server(int timeout) {
        if (publish_server.equals("")) {
            if (is_connected == true) {
                try {
                    data = util.step_9_server_received(key_session, iv_AES, udp_server, timeout);
                    String dados = new String(data.getData());
                    if (dados.equals("listen")) {
                        return "listen";
                    }
                    if (dados.equals("done")) {
                        is_connected = false;
                    }
                    String[] quebra = dados.split(delimiter);
                    if (quebra[0].equals("request")) {
                        if (quebra.length == 2) {
                            publish_server = quebra[1];
                        } else {
                            publish_server = "SERVER";
                        }
                        return quebra[0];
                    }
                    if (!dados.equals("timeOut")) {
                        if (verbose) {
                            System.out.println("DEVICE: " + data.getAddress().getHostAddress() + ":" + data.getPort());
                        }
                        util.step_9_server_send(key_session, iv_AES, udp_server, "ok", data.getAddress(), data.getPort());
                    }

                    return dados;
                } catch (IOException ex) {
                    System.out.println("ERRO try catch: " + ex.getMessage());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("Você não está conectado!");
                return "DESCONECTADO";
            }
        } else {
            System.out.println("Você não pode escutar por que:\nVocê deve adicionar "
                    + "o método 'publish_server()' após um request pelo servidor!");

        }
        return "ERRO";
    }

    public boolean publish_server(String data) {
        if (!publish_server.equals("")) {
            data = publish_server + ":" + data;
        }
        return server_publish(data, 0);
    }

    public boolean publish_server(String data, int timeout) {
        if (!publish_server.equals("")) {
            data = publish_server + ":" + data;
        }
        return server_publish(data, timeout);
    }

    private boolean server_publish(String data, int timeout) {
        if (!publish_server.equals("")) {
            try {
                util.step_9_server_send(key_session, iv_AES, udp_server, data, this.data.getAddress(), this.data.getPort());
                this.data = util.step_9_server_received(key_session, iv_AES, udp_server, timeout);
            } catch (Exception ex) {
                Logger.getLogger(IoTAuth_server.class.getName()).log(Level.SEVERE, null, ex);
            }
            String dados = new String(this.data.getData());
            if (dados.equals("done")) {
                is_connected = false;
                return false;
            } else if (dados.equals("ok")) {
                publish_server = "";
                return true;
            }
        } else {
            System.out.println("Você não pode escutar o método 'publish_server()' por que:\nVocê deve adicionar "
                    + "o método 'publish_server()' somente após um request do cliente!");
        }
        return false;
    }

    private boolean handshake(String ciphersuite, String ip, int porta) {
        if (verbose) {
            System.out.println("******** HANDSHAKE SERVIDOR ********\n");
        }
        int tamanho_iv = 16;

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
        double taxa_tempo = 10;
        /****************************************************************/

        if(algoritmos[0].equals("DH")){
            if(algoritmos[1].equals("RSA")) {
                algoritmo_DH_RSA = true;
            }else{
                System.out.println("ERRO NÃO HÁ CIPHER SUPORTADA: " + algoritmos[0] + "<<>> " + algoritmos[1]);
                return false;
            }
        }else if(algoritmos[0].equals("ECDHE")){
            /*
            * ECDSA is a digital signature algorithm
            * ECIES is an Integrated Encryption scheme
            * ECDHE is a key secure key exchange algorithm ephemeral
            */
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

        STEPS_data_server data = null;
        if (verbose) {
            System.out.println("\n******** STEP 1 ********\nPacket received");
            System.out.println("C->S: Syn, nA");
        }
        try {

            data = util.step_1_server(udp_server, InetAddress.getLocalHost().getHostAddress(), "SHA-512");

            if (data.erro.equals("")) {
                if (verbose){
                    System.out.println("\n******** STEP 2 ********\nPacket send");
                    System.out.println("S->C: Ack, nA, nB");
                }

                data = util.step_2_server(data);


                if (data.erro.equals("")) {
                    if (verbose) {
                        System.out.println("\n******** STEP 3 ********\nPacket received");
                        System.out.println("C->S: {KApub FdrA, nB, nA} Ass, tpA");
                    }
                    if(algoritmo_ECDHE_ECDSA) {
                        data = util.steps_3_server_EC(data, algoritmo_SHA, 300000);
                    }else if(algoritmo_ECDHE_RSA || algoritmo_DH_RSA) {
                        data = util.step_3_server_RSA(data, algoritmo_SHA, 300000);
                    }else{
                        return false;
                    }

                    if (data.erro.equals("")) {
                        if (verbose) {
                            System.out.println("\n******** STEP 4 ********\nPacket send");
                            System.out.println("S->C: {KBpub, F(KApub), FdrB, nA, nB} Ass, tpB");
                        }
                        if(algoritmo_ECDHE_ECDSA) {
                            data = util.step_4_server_EC(data, algoritmo_SHA, 10000);
                        }else if(algoritmo_ECDHE_RSA || algoritmo_DH_RSA) {
                            data = util.step_4_server_RSA(data, tam_chave_RSA, algoritmo_SHA, 10000);
                        }else{
                            return false;
                        }

                        if (data.erro.equals("")) {
                            if (verbose) {
                                System.out.println("\n******** STEP 5 ********\nPacket received");
                                System.out.println("C->S: {Ack, F(KBpub), nB, nA} Ass");
                            }
                            if(algoritmo_ECDHE_ECDSA) {
                                data = util.step_5_server_EC(data, algoritmo_SHA, taxa_tempo);
                            }else if(algoritmo_ECDHE_RSA || algoritmo_DH_RSA) {
                                data = util.step_5_server_RSA(data, algoritmo_SHA, taxa_tempo);
                            }else{
                                return false;
                            }

                            if (data.erro.equals("")) {
                                if (verbose) {
                                    System.out.println("\n******** STEP 6 ********\nPacket send");
                                    System.out.println("S->C: {{DHB, g, p, iv, nA, nB} Ass} Cif, tpB");
                                }
                                if(algoritmo_ECDHE_ECDSA || algoritmo_ECDHE_RSA) {
                                    data = util.step_6_server_EC(data, tamanho_iv, algoritmo_SHA);
                                }else if(algoritmo_DH_RSA) {
                                    data = util.step_6_server_RSA(data, tam_ger_dh, tamanho_iv, algoritmo_SHA);
                                }else{
                                    return false;
                                }

                                if (data.erro.equals("")) {
                                    if (verbose) {
                                        System.out.println("\n******** STEP 7 ********\nPacket received");
                                        System.out.println("C->S: {{DHA, nB, nA} Ass} Cif, tpA");
                                    }
                                    if(algoritmo_ECDHE_ECDSA || algoritmo_ECDHE_RSA) {
                                        data = util.step_7_server_EC(data, algoritmo_SHA, taxa_tempo);
                                    }else if(algoritmo_DH_RSA) {
                                        data = util.step_7_server_RSA(data, algoritmo_SHA,taxa_tempo);
                                    }else{
                                        return false;
                                    }

                                    if (data.erro.equals("")) {
                                        if (verbose) {
                                            System.out.println("\n******** STEP 8 ********\nPacket send");
                                            System.out.println("S->C: {Ack, nA}DHk");
                                        }
                                        iv_AES = data.iv_AES;
                                        if(algoritmo_ECDHE_ECDSA || algoritmo_ECDHE_RSA) {
                                            key_session = util.step_8_server_EC(data, porta);
                                        }else if(algoritmo_DH_RSA) {
                                            key_session = util.step_8_server_RSA(data, porta);
                                        }else{
                                            return false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!data.erro.equals("")) {
                System.out.println(data.erro);
            } else {
                return true;
            }
        } catch (Exception ex) {
            System.out.println("ERRO try catch: " + ex.getMessage());
        }
        return false;
    }
}

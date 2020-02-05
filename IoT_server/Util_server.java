
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.JSONObject;

/**
 * @author Leandro Loffi
 */
public class Util_server {

    Util util = new Util();
    boolean verbose;

    public Util_server(boolean verbose) {
        this.verbose = verbose;
    }

    public STEPS_data_server step_1_server(UDPserver udp, String ipSource, String algoritmoSHA) {
        long teste = System.currentTimeMillis();
        Random gerador = new Random();
        int seqNumber = gerador.nextInt(10000);
        DatagramPacket packet = null;
        try {
            packet = udp.receiveUDPserver(5000);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (packet == null){
            return new STEPS_data_server(0, udp, packet.getAddress(), ipSource, algoritmoSHA, "", seqNumber, "ERRO: Format Incorrect null", packet, teste+"");
        }
        JSONObject pacote = new JSONObject(new String(packet.getData()));
        if (verbose) {
            System.out.println("PACKET: " + pacote);
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            System.out.println("Step 1 time: " + teste + " ms");
        }
        if (pacote.length() != 2) {
            return new STEPS_data_server(0, udp, packet.getAddress(), ipSource, algoritmoSHA, "", seqNumber, "ERRO: Format Incorrect (length < 2)", packet, teste+"");
        }
        if(pacote.isNull("SYN") | pacote.isNull("nonce_A")){
            return new STEPS_data_server(0, udp, packet.getAddress(), ipSource, algoritmoSHA, "", seqNumber, "ERRO: Format Incorrect != SYN OR != nonce_A", packet, teste+"");
        }

        return new STEPS_data_server(0, udp, packet.getAddress(), ipSource, algoritmoSHA, (String) pacote.get("nonce_A"), seqNumber, "", packet, teste+"");
    }

    public STEPS_data_server step_2_server(STEPS_data_server data_server) {
        long teste = System.currentTimeMillis();
        data_server.nonce_B = util.getNonce(data_server.ipDest.getHostAddress(), data_server.ipSource, data_server.seqNumber, data_server.algorithmSHA);
        JSONObject obj = new JSONObject();
        obj.put("ACK", "Ack");
        obj.put("nonce_A", data_server.nonce_A);
        obj.put("nonce_B", data_server.nonce_B);
        if (verbose) {
            System.out.println("PACKET: " + obj.toString());
        }
        try {
            data_server.udp.sendUDPserver(obj.toString(), data_server.ipDest, data_server.data.getPort());
        } catch (Exception e) {
            e.printStackTrace();
        }
        data_server.time_network = System.currentTimeMillis();

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 2 time: " + teste);
        }
        return data_server;
    }


    public STEPS_data_server steps_3_server_EC(STEPS_data_server data_server, String algoritmo_SHA, int tempo){

        try {
            data_server.data = data_server.udp.receiveUDPserver(tempo);
            long teste = System.currentTimeMillis();
            data_server.time_network = System.currentTimeMillis() - data_server.time_network;
            data_server.tp_B = System.currentTimeMillis();
            String data = new String(data_server.data.getData());
            if ("timeOut".equals(data)) {
                data_server.erro = "ERROR: Time out (time > 5000 ms)";
                return data_server;
            }
            if(verbose){
                System.out.println("PACKET: " + data);
            }

            JSONObject obj = new JSONObject(data);
            if (obj.length() == 3) {

                String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
                algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
                Signature ecdsa1 = Signature.getInstance(algoritmo_SHA+"withECDSA");

                JSONObject mensagem = (JSONObject) obj.get("message");
                System.out.println(mensagem.toString());
                data_server.keys_ecc_A = new Key_elliptical_curves((String) mensagem.get("publicKey"));
                PublicKey publicKey = data_server.keys_ecc_A.getPublicKey();
                String assinatura = (String) obj.get("signature");
                String str = mensagem.toString();
                byte[] strByte = str.getBytes("UTF-8");
                ecdsa1.initVerify(publicKey);
                ecdsa1.update(strByte);
                byte[] signature = util.base64S_b(assinatura);
                boolean verify = ecdsa1.verify(signature);
                if(verbose){
                    System.out.println("ASSINATURA: " + verify);
                }
                if (verify) {
                    if (!mensagem.get("nonce_B").equals(data_server.nonce_B)) {
                        data_server.erro = "ERROR: Nonce Incorrect (Nonce_B != Nonce_B)";
                        return data_server;
                    }
                } else {
                    data_server.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                    return data_server;
                }
                data_server.nonce_A = (String) mensagem.get("nonce_A");
                data_server.Fdr_A = new FDR((String) mensagem.get("Fdr_A_op"), (Integer)mensagem.get("Fdr_A_valor"));
                data_server.tp_A = Long.valueOf((Integer) obj.get("tp_A"));

            } else {
                data_server.erro = "ERROR: Format Incorrect (length != 3) >> " + obj.length();
            }

            teste = System.currentTimeMillis() - teste;
            if (verbose) {
                data_server.list_time.add(teste+"");
                System.out.println("Step 3 time: " + teste);
            }
        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }


        return data_server;
    }

    public STEPS_data_server step_3_server_RSA(STEPS_data_server data_server, String algoritmo_SHA, int tempo) throws Exception {
        data_server.data = data_server.udp.receiveUDPserver(tempo);
        long teste = System.currentTimeMillis();
        data_server.time_network = System.currentTimeMillis() - data_server.time_network;
        data_server.tp_B = System.currentTimeMillis();
        String data = new String(data_server.data.getData());
        if ("timeOut".equals(data)) {
            data_server.erro = "ERROR: Time out (time > 5000 ms)";
            return data_server;
        }
        if (verbose) {
            System.out.println("PACKET: " + data);
        }

        JSONObject packet = new JSONObject(data);

        if (packet.length() == 3) {
            if(packet.isNull("message") | packet.isNull("signature") | packet.isNull("tp_A")){
                data_server.erro = "ERROR: Format Incorrect (!= message, != signature, != tp_A)";
            }else {

                JSONObject packet_2 = new JSONObject((String) packet.get("message"));
                if(packet_2.isNull("Kpub_A") | packet_2.isNull("Fdr_op_A") | packet_2.isNull("Fdr_val_A") |
                        packet_2.isNull("nonce_B") | packet_2.isNull("nonce_A")){
                    data_server.erro = "ERROR: Format Incorrect (!= Kpub_A, != Fdr_op_A, != Fdr_val_A, != nonce_B, != nonce_A)";
                }else {
                    data_server.keys_rsa_A = new Keys_RSA((String) packet_2.get("Kpub_A"), "RSA");
                    RSA rsa = new RSA("RSA");
                    SHA sha = new SHA(algoritmo_SHA);
                    String retorno_hash = rsa.decrypt_RSA_A(data_server.keys_rsa_A.getPublicKey(), (String) packet.get("signature"));
                    String hash = sha.getSHA(packet_2.toString());

                    if (hash.equals(retorno_hash)) {
                        if (!packet_2.get("nonce_B").equals(data_server.nonce_B)) {
                            data_server.erro = "ERROR: Nonce Incorrect (Nonce_B != Nonce_B)";
                            return data_server;
                        }
                    } else {
                        data_server.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                        return data_server;
                    }
                    data_server.nonce_A = (String) packet_2.get("nonce_A");
                    String Fdr = packet_2.getString("Fdr_op_A");
                    int valor = (Integer) packet_2.get("Fdr_val_A");
                    data_server.Fdr_A = new FDR(Fdr, valor);
                    data_server.tp_A = Long.valueOf((Integer) packet.get("tp_A"));
                }
            }
        } else {
            data_server.erro = "ERROR: Format Incorrect (length != 3)";
        }

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 3 time: " + teste);
        }
        return data_server;
    }
    long time_aux;

    public STEPS_data_server step_4_server_EC(STEPS_data_server data_server, String algoritmo_SHA, int tamanho_FDR){
        long teste = System.currentTimeMillis();
        time_aux = System.currentTimeMillis();

        // ***** Calcula da Parte B
        char[] asciiValue = util.base64b_S(data_server.keys_ecc_A.getPublicKey().getEncoded()).toCharArray();

        long response_Fdr_A = util.response_Fdr(data_server.Fdr_A, asciiValue);

        data_server.keys_ecc_B = new Key_elliptical_curves();
        data_server.Fdr_B = new FDR(tamanho_FDR);
        data_server.seqNumber += 1;
        data_server.nonce_B = util.getNonce(data_server.ipDest.getHostAddress(), data_server.ipSource, data_server.seqNumber, data_server.algorithmSHA);

        String chave_publica = util.base64b_S(data_server.keys_ecc_B.getPublicKey().getEncoded());

        // ***** Monta Pacote
        JSONObject packet = new JSONObject();
        packet.put("publicKey", chave_publica);
        packet.put("RFdr_A", response_Fdr_A);
        packet.put("Fdr_B_op", data_server.Fdr_B.operation);
        packet.put("Fdr_B_valor", data_server.Fdr_B.value);
        packet.put("nonce_A", data_server.nonce_A);
        packet.put("nonce_B", data_server.nonce_B);

        String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
        algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
        byte[] ass_packet = null;
        try {
            Signature ecdsa = Signature.getInstance(algoritmo_SHA+"withECDSA");

            ecdsa.initSign(data_server.keys_ecc_B.getPrivateKey());

            String str = packet.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa.update(strByte);
            ass_packet = ecdsa.sign();

            String signature = util.base64b_S(ass_packet);

            JSONObject packet_send = new JSONObject();
            packet_send.put("message", packet);
            packet_send.put("signature", signature);
            data_server.tp_B = System.currentTimeMillis() - data_server.tp_B;
            packet_send.put("tp_B", data_server.tp_B);

            data_server.udp.sendUDPserver(packet_send.toString(), data_server.ipDest, data_server.data.getPort());
            System.out.println("PACKET: " + packet_send.toString());

        } catch (NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        //time_aux = System.currentTimeMillis() - time_aux;

        data_server.time_network = data_server.time_network - time_aux;
        if (verbose) {
            System.out.println("Time Network: " + data_server.time_network + " ms");
        }

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 4 time: " + teste);
        }

        return data_server;
    }

    public STEPS_data_server step_4_server_RSA(STEPS_data_server data_server, int chave_RSA, String algoritmo_SHA, int tamanho_FDR) throws NoSuchAlgorithmException, Exception {
        long teste = System.currentTimeMillis();
        //time_aux = System.currentTimeMillis();

        // ***** Calcula da Parte B
        char[] asciiValue = data_server.keys_rsa_A.getPublicKey_S().toCharArray();
        long response_Fdr_A = util.response_Fdr(data_server.Fdr_A, asciiValue);

        data_server.keys_rsa_B = new Keys_RSA("RSA", chave_RSA);
        data_server.Fdr_B = new FDR(tamanho_FDR);
        data_server.seqNumber += 1;
        data_server.nonce_B = util.getNonce(data_server.ipDest.getHostAddress(), data_server.ipSource, data_server.seqNumber, data_server.algorithmSHA);

        // ***** Monta Pacote
        JSONObject packet_1 = new JSONObject();
        packet_1.put("Kpub_B", data_server.keys_rsa_B.getPublicKey_S());
        packet_1.put("RFdr_A", response_Fdr_A);
        packet_1.put("Fdr_op_B", data_server.Fdr_B.operation);
        packet_1.put("Fdr_val_B", data_server.Fdr_B.value);
        packet_1.put("nonce_A", data_server.nonce_A);
        packet_1.put("nonce_B", data_server.nonce_B);

        // ***** Calcula Assinatura
        SHA sha = new SHA(algoritmo_SHA);
        RSA rsa = new RSA("RSA");
        String hash_packet_1 = sha.getSHA(packet_1.toString());
        String ass_packet_1 = rsa.encrypt_RSA_A(data_server.keys_rsa_B.getPrivateKey(), hash_packet_1);

        data_server.tp_B = System.currentTimeMillis() - data_server.tp_B;

        if (data_server.tp_A > data_server.tp_B) {
            data_server.power_processing = "server";
        } else {
            data_server.power_processing = "client";
        }
        if (verbose) {
            System.out.println("MAIS FORTE: " + data_server.power_processing + " = " + data_server.tp_A + " A<>B " + data_server.tp_B);
        }
        JSONObject packet_send = new JSONObject();
        packet_send.put("message", packet_1.toString());
        packet_send.put("signature", ass_packet_1);
        packet_send.put("tp_B", data_server.tp_B);

        if (verbose) {
            System.out.println("PACKET: " + packet_send);
        }

        time_aux = System.currentTimeMillis() - time_aux;

        data_server.time_network = data_server.time_network - time_aux;
        if (verbose) {
            System.out.println("Time Network: " + data_server.time_network + " ms");
        }
        data_server.udp.sendUDPserver(packet_send.toString(), data_server.ipDest, data_server.data.getPort());

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 4 time: " + teste);
        }
        return data_server;
    }

    public STEPS_data_server step_5_server_EC(STEPS_data_server data_server, String algoritmo_SHA, double taxa){
        int tempo = (int) (data_server.tp_B + data_server.time_network);
        tempo = tempo + (int) (tempo * taxa);
        try {
            data_server.data = data_server.udp.receiveUDPserver(tempo);
            long teste = System.currentTimeMillis();

            String data = new String(data_server.data.getData());

            if ("timeOut".equals(data)) {
                data_server.erro = "ERROR: Time out (time > " + tempo + " ms)";
                return data_server;
            }
            if (verbose) {
                System.out.println("PACKET: " + data);
            }

            JSONObject packet = new JSONObject(data);

            if (packet.length() == 2) {

                JSONObject message = (JSONObject) packet.get("message");

                String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
                algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
                Signature ecdsa1 = Signature.getInstance(algoritmo_SHA+"withECDSA");

                PublicKey publicKey = data_server.keys_ecc_A.getPublicKey();
                String assinatura = (String) packet.get("signature");
                String str = message.toString();
                byte[] strByte = str.getBytes("UTF-8");
                ecdsa1.initVerify(publicKey);
                ecdsa1.update(strByte);
                byte[] signature = util.base64S_b(assinatura);
                boolean verify = ecdsa1.verify(signature);
                if(verbose) {
                    System.out.println("ASSINATURA: " + verify);
                }

                if (verify) {
                    if (!message.get("nonce_B").equals(data_server.nonce_B)) {
                        data_server.erro = "ERROR: Nonce Incorrect (Nonce_B != Nonce_B)";
                        return data_server;
                    }
                    char[] asciiValue = util.base64b_S(data_server.keys_ecc_B.getPublicKey().getEncoded()).toCharArray();
                    long response_Fdr_B_orginal = util.response_Fdr(data_server.Fdr_B, asciiValue);
                    long response_Fdr_B_recebida = Long.valueOf(message.getInt("RFdr_B"));
                    if(response_Fdr_B_recebida != response_Fdr_B_orginal){
                        data_server.erro = "ERROR: Response Incorrect (RFdr_B != RFdr_B)";
                        return data_server;
                    }
                } else {
                    data_server.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                    return data_server;
                }
                data_server.nonce_A = (String) message.get("nonce_A");
            } else {
                data_server.erro = "ERROR: Format Incorrect (length != 2)";
            }
            teste = System.currentTimeMillis() - teste;
            if (verbose) {
                data_server.list_time.add(teste+"");
                System.out.println("Step 5 time: " + teste);
            }

        } catch (IOException | NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }


        return data_server;
    }

    public STEPS_data_server step_5_server_RSA(STEPS_data_server data_server, String algoritmo_SHA, double taxa) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception {

        int tempo = (int) (data_server.tp_B + data_server.time_network);
        tempo = tempo + (int) (tempo * taxa);
        data_server.data = data_server.udp.receiveUDPserver(tempo);
        long teste = System.currentTimeMillis();
        String data = new String(data_server.data.getData());

        if ("timeOut".equals(data)) {
            data_server.erro = "ERROR: Time out (time > " + tempo + " ms)";
            return data_server;
        }
        if (verbose) {
            System.out.println("PACKET: " + data);
        }

        JSONObject packet = new JSONObject(data);

        if (packet.length() == 2) {
            if(packet.isNull("message") | packet.isNull("signature")){
                data_server.erro = "ERROR: Format Incorrect (!= message, != signature)";
            }else {
                JSONObject packet_2 = new JSONObject((String) packet.get("message"));
                if(packet_2.isNull("ACK") | packet_2.isNull("RFdr_B") | packet_2.isNull("nonce_A") | packet_2.isNull("nonce_B")){
                    data_server.erro = "ERROR: Format Incorrect (!= Kpub_B, != RFdr_A, != nonce_A, != nonce_B)";
                }else {
                    RSA rsa = new RSA("RSA");
                    SHA sha = new SHA(algoritmo_SHA);
                    String retorno_hash = rsa.decrypt_RSA_A(data_server.keys_rsa_A.getPublicKey(), packet.getString("signature"));
                    String hash = sha.getSHA(packet_2.toString());
                    if (hash.equals(retorno_hash)) {
                        if (!packet_2.getString("nonce_B").equals(data_server.nonce_B)) {
                            data_server.erro = "ERROR: Nonce Incorrect (Nonce_B != Nonce_B)";
                            return data_server;
                        }
                        char[] asciiValue = data_server.keys_rsa_B.getPublicKey_S().toCharArray();
                        long response_Fdr_B_orginal = util.response_Fdr(data_server.Fdr_B, asciiValue);
                        long response_Fdr_B_recebida = Long.valueOf(packet_2.getInt("RFdr_B"));
                        if (response_Fdr_B_recebida != response_Fdr_B_orginal) {
                            data_server.erro = "ERROR: Response Incorrect (RFdr_B != RFdr_B)";
                            return data_server;
                        }
                    } else {
                        data_server.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                        return data_server;
                    }
                    data_server.nonce_A = packet_2.getString("nonce_A");
                }
            }
        } else {
            data_server.erro = "ERROR: Format Incorrect (length != 2)";
        }

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 5 time: " + teste);
        }
        return data_server;
    }

    public STEPS_data_server step_6_server_EC(STEPS_data_server data_server, int tamanho_iv, String algoritmo_SHA){
        long teste = System.currentTimeMillis();
        data_server.tp_B = System.currentTimeMillis();

        //***** GERANDO Diffie-Hellmann

        data_server.ecdhe = new ECDHE();
        byte[] ourPk = data_server.ecdhe.kp_B.getPublicKey().getEncoded();
        String chave_publica = util.base64b_S(ourPk);
        if(verbose) {
            System.out.println("Public Key: " + chave_publica);
        }
        // ****** GERANDO Nonce B
        data_server.nonce_B = util.getNonce(data_server.ipDest.getHostAddress(), data_server.ipSource, data_server.seqNumber, data_server.algorithmSHA);

        // ****** GERANDO IV
        Random r = new Random();
        for (int i = 0; i < tamanho_iv; i++) {
            data_server.iv_AES = data_server.iv_AES + r.nextInt(10);
        }
        if (verbose) {
            System.out.println("IV: " + data_server.iv_AES + " (size: " + data_server.iv_AES.length() + ")");
        }
        // ****** Montar pacote 1
        JSONObject packet = new JSONObject();

        packet.put("PublicKey_kp_B", chave_publica);
        packet.put("iv_AES", data_server.iv_AES);
        packet.put("nonce_A", data_server.nonce_A);
        packet.put("nonce_B", data_server.nonce_B);

        String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
        algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
        try {
            Signature ecdsa = Signature.getInstance(algoritmo_SHA+"withECDSA");
            ecdsa.initSign(data_server.keys_ecc_B.getPrivateKey());
            String str = packet.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa.update(strByte);
            byte[] ass_packet = ecdsa.sign();
            String signature = util.base64b_S(ass_packet);

            JSONObject packet_2 = new JSONObject();

            packet_2.put("message", packet.toString());
            packet_2.put("signature", signature);
            if(verbose) {
                System.out.println("Signature: " + signature);
            }
            String encryption = util.encryption_ECIES(data_server.keys_ecc_A.getPublicKey(), packet_2.toString());

            JSONObject packet_send = new JSONObject();
            packet_send.put("encryption", encryption);
            data_server.tp_B = System.currentTimeMillis() - data_server.tp_B;
            packet_send.put("tp_B", data_server.tp_B);

            if (verbose) {
                System.out.println("PACKET: " + packet_send);
            }
            data_server.udp.sendUDPserver(packet_send.toString(), data_server.ipDest, data_server.data.getPort());

        } catch (NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 6 time: " + teste);
        }
        return data_server;
    }


    public STEPS_data_server step_6_server_RSA(STEPS_data_server data_server, int tam_ger_dh, int tamanho_iv, String algoritmo_SHA) throws Exception {
        long teste = System.currentTimeMillis();
        data_server.tp_B = System.currentTimeMillis();

        //***** GERANDO Diffie-Hellmann
        data_server.dh = new DH();
        data_server.dh.generate_P_G(tam_ger_dh);

        data_server.values_dh = data_server.dh.generatePublicKey(null, tam_ger_dh, verbose);
        if (verbose) {
            System.out.println("P = " + data_server.values_dh.P.toString(16));
            System.out.println("G = " + data_server.values_dh.G.toString(16));
        }
        // ****** GERANDO Nonce B
        data_server.nonce_B = util.getNonce(data_server.ipDest.getHostAddress(), data_server.ipSource, data_server.seqNumber, data_server.algorithmSHA);

        // ****** GERANDO IV
        Random r = new Random();
        for (int i = 0; i < tamanho_iv; i++) {
            data_server.iv_AES = data_server.iv_AES + r.nextInt(10);
        }
        if (verbose) {
            System.out.println("IV: " + data_server.iv_AES + " (size: " + data_server.iv_AES.length() + ")");
        }
        // ****** Montar pacote 1
        String DH_B = util.base64b_S(data_server.values_dh.myPublicKey);

        JSONObject packet_1 = new JSONObject();
        packet_1.put("DH_B", DH_B);
        packet_1.put("G", data_server.values_dh.G.toString(16));
        packet_1.put("P", data_server.values_dh.P.toString(16));
        packet_1.put("iv_AES", data_server.iv_AES);
        packet_1.put("nonce_A", data_server.nonce_A);
        packet_1.put("nonce_B", data_server.nonce_B);

        // ***** Calcula Assinatura
        SHA sha = new SHA(algoritmo_SHA);
        RSA rsa = new RSA("RSA");
        String hash_packet_1 = sha.getSHA(packet_1.toString());
        String ass_packet_1 = rsa.encrypt_RSA_A(data_server.keys_rsa_B.getPrivateKey(), hash_packet_1);
        // ****** Montar pacote 2
        JSONObject packet_2 = new JSONObject();
        packet_2.put("message", packet_1.toString());
        packet_2.put("signature", ass_packet_1);

        int tamanho_bloco = 244;
        int v = (packet_2.toString().length() / tamanho_bloco) + 1;
        String packet_2_enc = v + "";
        int k = 0;
        for (int i = 0; i < v; i++) {
            String st = "";
            if (i == (v - 1)) {
                st = packet_2.toString().substring(i * (tamanho_bloco) - k, packet_2.toString().length());
            } else {
                st = packet_2.toString().substring((i * (tamanho_bloco)) - k, (i + 1) * (tamanho_bloco - 1));
            }
            k = k + 1;
            packet_2_enc = packet_2_enc + ";" + rsa.encrypt_RSA_E(data_server.keys_rsa_A.getPublicKey(), st);

        }

        // ****** Montar pacote 3 e enviar
        JSONObject packet_send = new JSONObject();
        packet_send.put("encryption", packet_2_enc);
        data_server.tp_B = System.currentTimeMillis() - data_server.tp_B;
        packet_send.put("tp_B", data_server.tp_B);

        if (verbose) {
            System.out.println("PACKET: " + packet_send);
        }
        data_server.udp.sendUDPserver(packet_send.toString(), data_server.ipDest, data_server.data.getPort());

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 6 time: " + teste);
        }
        return data_server;
    }

    public STEPS_data_server step_7_server_EC(STEPS_data_server data_server, String algoritmo_SHA, double taxa) {

        int tempo = 5000;//(int) ((data_server.tp_B * 2) + data_server.time_network);
        tempo = tempo + (int) (tempo * taxa);
        try {
            data_server.data = data_server.udp.receiveUDPserver(tempo);
            long teste = System.currentTimeMillis();

            String data = new String(data_server.data.getData());
            if ("timeOut".equals(data)) {
                data_server.erro = "ERROR: Time out (time > " + tempo + " ms)";
                return data_server;
            }
            if (verbose) {
                System.out.println("PACKET: " + data);
            }

            JSONObject obj = new JSONObject(data);

            data_server.tp_A = Long.valueOf((Integer) obj.get("tp_A"));
            String encryption = (String) obj.get("encryption");
            String saida = util.decryption_ECIES(data_server.keys_ecc_B.getPrivateKey(), encryption);

            JSONObject decryption = new JSONObject(saida);
            JSONObject mensagem = (JSONObject) decryption.get("message");
            if(verbose) {
                System.out.println("Message: " + mensagem);
            }
            String chave_publica = (String) mensagem.get("PublicKey_kp_A");
            data_server.ecdhe.set_Kp_A(chave_publica);

            String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
            algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
            Signature ecdsa1 = Signature.getInstance(algoritmo_SHA+"withECDSA");

            PublicKey publicKey = data_server.keys_ecc_A.getPublicKey();
            String assinatura = (String) decryption.get("signature");
            if(verbose){
                System.out.println("Signature: " + assinatura);
            }
            String str = mensagem.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa1.initVerify(publicKey);
            ecdsa1.update(strByte);
            byte[] signature = util.base64S_b(assinatura);
            boolean verify = ecdsa1.verify(signature);
            if(verbose) {
                System.out.println("ASSINATURA: " + verify);
            }

            if (!verify) {
                data_server.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                return data_server;
            }
            if (!mensagem.get("nonce_B").equals(data_server.nonce_B)) {
                data_server.erro = "ERROR: Nonce Incorrect (Nonce_A != Nonce_A)";
                return data_server;
            }

            data_server.nonce_A = (String) mensagem.get("nonce_A");

            data_server.ecdhe.setSharedSecret(data_server.ecdhe.kp_A.getPublicKey());

            data_server.key_session = data_server.ecdhe.getSharedSecret();

            teste = System.currentTimeMillis() - teste;
            if (verbose) {
                data_server.list_time.add(teste+"");
                System.out.println("Step 7 time: " + teste);
            }

        } catch (IOException | InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return data_server;
    }

    public STEPS_data_server step_7_server_RSA(STEPS_data_server data_server, String algoritmo_SHA, double taxa) throws Exception {

        int tempo = (int) ((data_server.tp_B * 2) + data_server.time_network);
        tempo = tempo + (int) (tempo * taxa);
        data_server.data = data_server.udp.receiveUDPserver(tempo);
        long teste = System.currentTimeMillis();

        String data = new String(data_server.data.getData());
        if ("timeOut".equals(data)) {
            data_server.erro = "ERROR: Time out (time > " + tempo + " ms)";
            return data_server;
        }
        if (verbose) {
            System.out.println("PACKET: " + data);
        }
        JSONObject packet_1 = new JSONObject(data);

        String[] quebras_1 = packet_1.getString("encryption").split(";");
        int v = Integer.valueOf(quebras_1[0]);

        String packet_aux = "";
        RSA rsa = new RSA("RSA");
        SHA sha = new SHA(algoritmo_SHA);

        for (int i = 1; i <= v; i++) {
            packet_aux = packet_aux + rsa.decrypt_RSA_E(data_server.keys_rsa_B.getPrivateKey(), quebras_1[i]);
        }
        JSONObject packet_2 = new JSONObject(packet_aux);

        // ****** VERIFICAR ASSINATURA (HASH)
        String retorno_hash = rsa.decrypt_RSA_A(data_server.keys_rsa_A.getPublicKey(), packet_2.getString("signature"));
        String hash = sha.getSHA(packet_2.getString("message"));

        if (!retorno_hash.equals(hash)) {
            data_server.erro = "ERROR: Hash Incorrect (Hash 1 != Hash 2)";
            if (verbose) {
                System.out.println("Hash 1:" + retorno_hash + "\nHash 2:" + hash);
            }
            return data_server;
        }

        JSONObject packet_3 = new JSONObject(packet_2.getString("message"));

        if (!data_server.nonce_B.equals(packet_3.getString("nonce_B"))) {
            if (verbose) {
                System.out.println("Nonce 1: " + data_server.nonce_B + "\nNonce 2: " + packet_3.getString("nonce_B"));
            }
            data_server.erro = "ERROR: Nonce Incorrect (Nonce_B != Nonce_B)";
            return data_server;
        }
        data_server.nonce_A = packet_3.getString("nonce_A");
        data_server.values_dh.myPublicKey = util.base64S_b(packet_3.getString("DH_A"));

        data_server.key_session = data_server.dh.computeSharedKey(data_server.values_dh.myPublicKey);

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            System.out.println("Step 7 time: " + teste);
        }
        return data_server;
    }

    public String step_8_server_EC(STEPS_data_server data_server, int porta) {
        long teste = System.currentTimeMillis();
        byte[] key_session = data_server.key_session;

        JSONObject obj = new JSONObject();
        obj.put("Ack", "Ack");
        obj.put("nonce_A", data_server.nonce_A);

        AES aes = new AES();
        JSONObject packet_send = new JSONObject();
        try {
            packet_send.put("encryption", aes.encrypt_AES(obj.toString(), util.base64b_S(key_session), data_server.iv_AES));
            if (verbose) {
                System.out.println("PACKET: " + packet_send.toString());
            }

            data_server.udp.sendUDPserver(packet_send.toString(), data_server.ipDest, data_server.data.getPort());

        } catch (Exception ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        if (verbose) {
            System.out.println("SESSION KEY: " + util.base64b_S(key_session));
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            util.write_data_txt(data_server.list_time, "planilha_fog_"+porta);
            System.out.println("Step 8 time: " + teste);
        }
        System.out.println("\nTUDO OK!\n");
        return util.base64b_S(key_session);
    }

    public String step_8_server_RSA(STEPS_data_server data_server, int porta) throws Exception {
        long teste = System.currentTimeMillis();
        byte[] key_session = data_server.key_session;

        JSONObject packet_1 = new JSONObject();
        packet_1.put("ACK", "Ack");
        packet_1.put("nonce_A", data_server.nonce_A);

        AES aes = new AES();
        JSONObject packet_send = new JSONObject();
        try {
            packet_send.put("dados", aes.encrypt_AES(packet_1.toString(), util.base64b_S(key_session), data_server.iv_AES));
            if (verbose) {
                System.out.println("PACKET: " + packet_send);
            }

        } catch (UnsupportedEncodingException
                | InvalidKeyException
                | NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        data_server.udp.sendUDPserver(packet_send.toString(), data_server.ipDest, data_server.data.getPort());
        if (verbose) {
            System.out.println("SESSION KEY: " + util.base64b_S(key_session));
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            data_server.list_time.add(teste+"");
            util.write_data_txt(data_server.list_time, "planilha_fog_"+porta);
            System.out.println("Step 8 time: " + teste);
        }

        System.out.println("\nTUDO OK!\n");
        return util.base64b_S(key_session);
    }

    public void step_9_server_send(String key_session, String iv, UDPserver udp, String packet_send, InetAddress ip_dest, int port) throws Exception {
        AES aes = new AES();
        JSONObject obj = new JSONObject();
        obj.put("dados", aes.encrypt_AES(packet_send, key_session, iv));

        udp.sendUDPserver(obj.toString(), ip_dest, port);
    }

    public DatagramPacket step_9_server_received(String key_session, String iv, UDPserver udp, int timeOut) throws Exception {
        AES aes = new AES();
        DatagramPacket data = null;
        if (timeOut == 0) {
            data = udp.receiveUDPserver();
        } else {
            data = udp.receiveUDPserver(timeOut);
        }

        JSONObject obj = new JSONObject(new String(data.getData()));
        if (!data.getData().equals("timeOut")) {
            try {
                String data1 = aes.decrypt_AES((String) obj.get("dados"), key_session, iv);
                data.setData(data1.getBytes());
            } catch (GeneralSecurityException ex) {
                System.out.println("ERRO try catch: " + ex.getMessage());
            }
        }
        return data;
    }
}


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.json.JSONObject;

/**
 *
 * @author leandro Loffi
 */
public class Util_client {

    private boolean verbose;

    Util_client(boolean verbose) {
        this.verbose = verbose;
    }

    Util util = new Util();

    public STEPS_data_client step_1_client(UDPClient udp, String ipDest, String ipSource, String algoritmoSHA) {
        long teste = System.currentTimeMillis();
        Random gerador = new Random();
        int seqNumber = gerador.nextInt(10000);
        String nonce_A = util.getNonce(ipDest, ipSource, seqNumber, algoritmoSHA);
        JSONObject obj = new JSONObject();
        obj.put("SYN", "Syn");
        obj.put("nonce_A", nonce_A);
        if (verbose) {
            System.out.println("PACKET: " + obj.toString());
        }
        try {
            udp.SendUDPclient(obj.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        long time_network = System.currentTimeMillis();
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            System.out.println("Step 1 time: " + teste);
        }
        return new STEPS_data_client(time_network, udp, ipDest, ipSource, algoritmoSHA, nonce_A, seqNumber, teste+"");
    }

    public STEPS_data_client step_2_client(STEPS_data_client data){
        try {
            data.data = data.udp.receiveUDPclient(5000);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long teste = System.currentTimeMillis();
        data.tp_A = System.currentTimeMillis();
        data.time_network = System.currentTimeMillis() - data.time_network;
        if ("timeOut".equals(data.data)) {
            data.erro = "ERRO: Time out (time > 5000 ms)";
            return data;
        }
        if (verbose) {
            System.out.println("PACKET: " + data.data);
        }
        if (verbose) {
            System.out.println("Time Network: " + data.time_network + " ms");
        }
        JSONObject pacote = new JSONObject(data.data);
        if (pacote.length() == 3) {
            if(pacote.isNull("ACK") | pacote.isNull("nonce_A") | pacote.isNull("nonce_B")){
                data.erro = "ERROR: Format Incorrect (isNULL!))";
            }else {
                if ("Ack".equals(pacote.get("ACK"))) {
                    if (pacote.get("nonce_A").equals(data.nonce_A)) {
                        data.nonce_B = (String) pacote.get("nonce_B");
                    } else {
                        data.erro = "ERROR: Nonce Incorrect (No match)";
                    }
                } else {
                    data.erro = "ERROR: Format Incorrect (\"Ack\".equals)";
                }
            }
        } else {
            if(pacote.isNull("DONE")){
                data.erro = "ERROR: Server done";
            }else {
                data.erro = "ERROR: Format Incorrect (length != 3)";
            }
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data.time_values.add(teste+"");
            System.out.println("Step 2 time: " + teste);
        }
        return data;
    }

    public STEPS_data_client steps_3_client_EC(STEPS_data_client data_client, String algoritmo_SHA, int tamanho_FDR){
        long teste = System.currentTimeMillis();

        data_client.keys_ecc_A = new Key_elliptical_curve();
        data_client.Fdr_A = new FDR(tamanho_FDR);

        data_client.seqNumber += 1;
        data_client.nonce_A = util.getNonce(data_client.ipDest, data_client.ipSource, data_client.seqNumber, algoritmo_SHA);

        String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
        algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];

        String chave_publica = util.Base64b_S(data_client.keys_ecc_A.getPublicKey().getEncoded());

        JSONObject packet = new JSONObject();
        packet.put("publicKey",  chave_publica);
        packet.put("Fdr_A_op",   data_client.Fdr_A.operation);
        packet.put("Fdr_A_valor", data_client.Fdr_A.value);
        packet.put("nonce_B",    data_client.nonce_B);
        packet.put("nonce_A",    data_client.nonce_A);

        byte[] ass_packet = null;
        try {
            Signature ecdsa = Signature.getInstance(algoritmo_SHA+"withECDSA");

            ecdsa.initSign(data_client.keys_ecc_A.getPrivateKey());

            String str = packet.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa.update(strByte);
            ass_packet = ecdsa.sign();

            String signature = util.Base64b_S(ass_packet);

            JSONObject packet_send = new JSONObject();
            packet_send.put("message", packet);
            packet_send.put("signature", signature);
            data_client.tp_A = System.currentTimeMillis() - data_client.tp_A;
            packet_send.put("tp_A", data_client.tp_A);

            data_client.udp.SendUDPclient(packet_send.toString());
            System.out.println("PACKET: " + packet_send);

        } catch (NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("Step 3 time: " + teste);
        }
        return data_client;
    }

    public STEPS_data_client step_3_client_RSA(STEPS_data_client data_client, String delimitador, int chave_RSA, String algoritmo_SHA, int tamanho_FDR) throws NoSuchAlgorithmException, Exception {
        long teste = System.currentTimeMillis();
        data_client.keys_rsa_A = new Keys_RSA("RSA", chave_RSA);
        data_client.Fdr_A = new FDR(tamanho_FDR);
        if (verbose) {
            System.out.println("Fdr A: " + data_client.Fdr_A.operation + " " + data_client.Fdr_A.value);
        }
        data_client.seqNumber += 1;
        data_client.nonce_A = util.getNonce(data_client.ipDest, data_client.ipSource, data_client.seqNumber, algoritmo_SHA);

        JSONObject packet_1 = new JSONObject();
        packet_1.put("Kpub_A", data_client.keys_rsa_A.getPublicKey_S());
        packet_1.put("Fdr_op_A", data_client.Fdr_A.operation);
        packet_1.put("Fdr_val_A", data_client.Fdr_A.value);
        packet_1.put("nonce_B", data_client.nonce_B);
        packet_1.put("nonce_A", data_client.nonce_A);

        SHA sha = new SHA(algoritmo_SHA);
        RSA rsa = new RSA("RSA");
        String hash_packet_1 = sha.getSHA(packet_1.toString());
        String ass_packet_1 = rsa.encrypt_RSA_A(data_client.keys_rsa_A.getPrivateKey(), hash_packet_1);

        JSONObject packet_send = new JSONObject();
        packet_send.put("message", packet_1.toString());
        packet_send.put("signature", ass_packet_1);
        data_client.tp_A = System.currentTimeMillis() - data_client.tp_A;
        packet_send.put("tp_A", data_client.tp_A);

        if (verbose) {
            System.out.println("PACKET: " + packet_send);
        }

        data_client.udp.SendUDPclient(packet_send.toString());
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 3 time: " + teste);
        }
        return data_client;
    }

    public STEPS_data_client step_4_client_EC(STEPS_data_client data_client, double taxa, String algoritmo_SHA) throws Exception {

        int tempo = (int) (data_client.tp_A + data_client.time_network);
        tempo = tempo + (int) (tempo * taxa);
        data_client.data = data_client.udp.receiveUDPclient(tempo);
        long teste = System.currentTimeMillis();
        if ("timeOut".equals(data_client.data)) {
            data_client.erro = "ERRO: Time out (time > " + tempo + " ms)";
            return data_client;
        }
        JSONObject packet = new JSONObject(data_client.data);

        if (verbose) {
            System.out.println("PACKET: " + data_client.data);
        }

        if (packet.length() == 3) {
            JSONObject message = (JSONObject) packet.get("message");
            data_client.keys_ecc_B = new Key_elliptical_curve(message.getString("publicKey"));

            String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
            algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
            Signature ecdsa1 = Signature.getInstance(algoritmo_SHA+"withECDSA");

            PublicKey publicKey = data_client.keys_ecc_B.getPublicKey();
            String assinatura = packet.getString("signature");
            String str = message.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa1.initVerify(publicKey);
            ecdsa1.update(strByte);
            byte[] signature = util.Base64S_b(assinatura);
            boolean verify = ecdsa1.verify(signature);
            if(verbose) {
                System.out.println("ASSINATURA: " + verify);
            }
            if (verify) {

                if (!message.get("nonce_A").equals(data_client.nonce_A)) {
                    data_client.erro = "ERROR: Nonce Incorrect (Nonce_A != Nonce_A)";
                    return data_client;
                }
                char[] asciiValue = util.Base64b_S(data_client.keys_ecc_A.getPublicKey().getEncoded()).toCharArray();
                long response_Fdr_A_orginal = util.response_Fdr(data_client.Fdr_A, asciiValue);
                long response_Fdr_A_recebida = Long.valueOf(message.getInt("RFdr_A"));
                if(response_Fdr_A_recebida != response_Fdr_A_orginal){
                    data_client.erro = "ERROR: Response Incorrect (RFdr_A != RFdr_A)";
                    return data_client;
                }
            } else {
                data_client.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                return data_client;
            }
            data_client.nonce_B = message.getString("nonce_B");
            data_client.Fdr_B = new FDR(message.getString("Fdr_B_op"), message.getInt("Fdr_B_valor"));
            data_client.tp_B = Long.valueOf(packet.getInt("tp_B"));

        } else {
            if(packet.isNull("DONE")){
                data_client.erro = "ERROR: Server done";
            }else {
                data_client.erro = "ERROR: Format Incorrect";
            }
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 4 time: " + teste);
        }
        return data_client;
    }

    public STEPS_data_client step_4_client_RSA(STEPS_data_client data_client, double taxa, String delimitador, String algoritmo_SHA) throws Exception {
        int tempo = (int) (data_client.tp_A + data_client.time_network);
        tempo = tempo + (int) (tempo * taxa);
        data_client.data = data_client.udp.receiveUDPclient(tempo);
        long teste = System.currentTimeMillis();
        if ("timeOut".equals(data_client.data)) {
            data_client.erro = "ERRO: Time out (time > " + tempo + " ms)";
            return data_client;
        }

        JSONObject packet = new JSONObject(data_client.data);
        if (verbose) {
            System.out.println("PACKET: " + data_client.data);
        }
        if (packet.length() == 3) {
            if(packet.isNull("message") | packet.isNull("signature") | packet.isNull("tp_B")){
                data_client.erro = "ERROR: Format Incorrect (!= message, != signature, != tp_B)";
            }else {
                JSONObject packet_2 = new JSONObject((String) packet.get("message"));
                if(packet_2.isNull("Kpub_B") | packet_2.isNull("RFdr_A") | packet_2.isNull("Fdr_op_B")
                        | packet_2.isNull("Fdr_val_B") | packet_2.isNull("nonce_A") | packet_2.isNull("nonce_B")){
                    data_client.erro = "ERROR: Format Incorrect (!= Kpub_B, != RFdr_A, != Fdr_op_B, != Fdr_val_B, != nonce_A, != nonce_B)";
                }else {
                    data_client.keys_rsa_B = new Keys_RSA(packet_2.getString("Kpub_B"), "RSA");

                    RSA rsa = new RSA("RSA");
                    SHA sha = new SHA(algoritmo_SHA);
                    String retorno_hash = rsa.decrypt_RSA_A(data_client.keys_rsa_B.getPublicKey(), packet.getString("signature"));
                    String hash = sha.getSHA(packet.getString("message"));
                    if (hash.equals(retorno_hash)) {
                        if (!packet_2.getString("nonce_A").equals(data_client.nonce_A)) {
                            data_client.erro = "ERROR: Nonce Incorrect (Nonce_B != Nonce_B)";
                            return data_client;
                        }
                        char[] asciiValue = data_client.keys_rsa_A.getPublicKey_S().toCharArray();
                        long response_Fdr_A_orginal = util.response_Fdr(data_client.Fdr_A, asciiValue);
                        long response_Fdr_A_recebida = Long.valueOf(packet_2.getInt("RFdr_A"));
                        if(response_Fdr_A_recebida != response_Fdr_A_orginal){
                            data_client.erro = "ERROR: Response Incorrect (RFdr_A != RFdr_A)";
                            return data_client;
                        }
                    } else {
                        data_client.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                        return data_client;
                    }
                    data_client.nonce_B = packet_2.getString("nonce_B");
                    data_client.Fdr_B = new FDR(packet_2.getString("Fdr_op_B"), packet_2.getInt("Fdr_val_B"));
                    data_client.tp_B = Long.valueOf(packet.getInt("tp_B"));
                }
            }
        } else {
            if(packet.isNull("DONE")){
                data_client.erro = "ERROR: Server done";
            }else {
                data_client.erro = "ERROR: Format Incorrect";
            }
        }
        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 4 time: " + teste);
        }
        return data_client;
    }

    public STEPS_data_client step_5_client_EC(STEPS_data_client data_client, String algoritmo_SHA) throws Exception {
        long teste = System.currentTimeMillis();
        char[] asciiValue = util.Base64b_S(data_client.keys_ecc_B.getPublicKey().getEncoded()).toCharArray();
        long response_Fdr_B = util.response_Fdr(data_client.Fdr_B, asciiValue);
        data_client.nonce_A = util.getNonce(data_client.ipDest, data_client.ipSource, data_client.seqNumber, algoritmo_SHA);

        JSONObject packet = new JSONObject();

        packet.put("Ack", "Ack");
        packet.put("RFdr_B", response_Fdr_B);
        packet.put("nonce_B", data_client.nonce_B);
        packet.put("nonce_A", data_client.nonce_A);

        String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
        algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
        byte[] ass_packet = null;
        try {
            Signature ecdsa = Signature.getInstance(algoritmo_SHA+"withECDSA");

            ecdsa.initSign(data_client.keys_ecc_A.getPrivateKey());

            String str = packet.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa.update(strByte);
            ass_packet = ecdsa.sign();

            String signature = util.Base64b_S(ass_packet);

            JSONObject packet_send = new JSONObject();

            packet_send.put("message", packet);
            packet_send.put("signature", signature);

            if (verbose) {
                System.out.println("PACKET: " + packet_send);
            }
            data_client.udp.SendUDPclient(packet_send.toString());

        } catch (NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 5 time: " + teste);
        }

        return data_client;
    }

    public STEPS_data_client step_5_client_RSA(STEPS_data_client data_client, String delimitador, String algoritmo_SHA) throws Exception {
        long teste = System.currentTimeMillis();
        char[] asciiValue = data_client.keys_rsa_B.getPublicKey_S().toCharArray();
        long response_Fdr_B = util.response_Fdr(data_client.Fdr_B, asciiValue);
        data_client.nonce_A = util.getNonce(data_client.ipDest, data_client.ipSource, data_client.seqNumber, algoritmo_SHA);

        JSONObject packet = new JSONObject();
        packet.put("ACK", "Ack");
        packet.put("RFdr_B", response_Fdr_B);
        packet.put("nonce_B", data_client.nonce_B);
        packet.put("nonce_A", data_client.nonce_A);

        RSA rsa = new RSA("RSA");
        SHA sha = new SHA(algoritmo_SHA);

        String hash_packet_1 = sha.getSHA(packet.toString());
        String ass_packet_1 = rsa.encrypt_RSA_A(data_client.keys_rsa_A.getPrivateKey(), hash_packet_1);

        JSONObject packet_send = new JSONObject();
        packet_send.put("message", packet.toString());
        packet_send.put("signature", ass_packet_1);

        if (verbose) {
            System.out.println("PACKET: " + packet_send.toString());
        }
        data_client.udp.SendUDPclient(packet_send.toString());

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 5 time: " + teste);
        }

        return data_client;
    }

    public STEPS_data_client step_6_client_EC(STEPS_data_client data_client, String algoritmo_SHA, int tempo) throws Exception {
        data_client.data = data_client.udp.receiveUDPclient(tempo);
        long teste = System.currentTimeMillis();
        data_client.tp_A = System.currentTimeMillis();
        if(data_client.data.equals("timeOut")) {
            data_client.erro = "ERRO: Time out (time > " + tempo + " ms)";
            return data_client;
        }else {
            JSONObject packet = new JSONObject(data_client.data);
            if (verbose) {
                System.out.println("PACKET: " + data_client.data);
            }
            if (packet.length() == 2) {
                if (packet.isNull("encryption") | packet.isNull("tp_B")) {
                    data_client.erro = "ERROR: Format Incorrect (!= encryption, != tp_B)";
                } else {
                    data_client.tp_B = Long.valueOf(packet.getInt("tp_B"));
                    String encryption = packet.getString("encryption");
                    String saida = util.decryption_ECIES(data_client.keys_ecc_A.getPrivateKey(), encryption);

                    JSONObject decryption = new JSONObject(saida);
                    if (decryption.isNull("message") | decryption.isNull("signature")) {
                        data_client.erro = "ERROR: Format Incorrect (!= message, != signature)";
                    } else {
                        JSONObject mensagem = new JSONObject(decryption.getString("message"));
                        if (mensagem.isNull("PublicKey_kp_B") | mensagem.isNull("iv_AES") | mensagem.isNull("nonce_A") | mensagem.isNull("nonce_B")) {
                            data_client.erro = "ERROR: Format Incorrect (!= PublicKey_kp_B, != iv_AES, != nonce_A, != nonce_B)";
                        } else {
                            if (verbose) {
                                System.out.println("Message: " + mensagem);
                            }
                            data_client.ecdhe = new ECDHE();
                            String chave_publica = (String) mensagem.get("PublicKey_kp_B");

                            data_client.ecdhe.set_Kp_B(chave_publica);

                            String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
                            algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];
                            Signature ecdsa1 = Signature.getInstance(algoritmo_SHA + "withECDSA");

                            PublicKey publicKey = data_client.keys_ecc_B.getPublicKey();
                            String assinatura = (String) decryption.get("signature");
                            if (verbose) {
                                System.out.println("Signature: " + assinatura);
                            }
                            String str = mensagem.toString();
                            byte[] strByte = str.getBytes("UTF-8");
                            ecdsa1.initVerify(publicKey);
                            ecdsa1.update(strByte);
                            byte[] signature = util.Base64S_b(assinatura);
                            boolean verify = ecdsa1.verify(signature);
                            if (verbose) {
                                System.out.println("ASSINATURA: " + verify);
                            }

                            if (!verify) {
                                data_client.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                                return data_client;
                            }
                            if (!mensagem.get("nonce_A").equals(data_client.nonce_A)) {
                                data_client.erro = "ERROR: Nonce Incorrect (Nonce_A != Nonce_A)";
                                return data_client;
                            }
                            data_client.nonce_B = (String) mensagem.get("nonce_B");
                            data_client.iv_AES = (String) mensagem.get("iv_AES");

                            teste = System.currentTimeMillis() - teste;
                            if (verbose) {
                                //util.salvarDadosTxt(teste + "");
                                data_client.time_values.add(teste+"");
                                System.out.println("step 6 time: " + teste);
                            }
                        }
                    }
                }
            }else{
                if(packet.isNull("DONE")){
                    data_client.erro = "ERROR: Server done";
                }else {
                    data_client.erro = "ERROR: Format Incorrect (length != 2)";
                }
            }
        }
        return data_client;
    }

    public STEPS_data_client step_6_client_RSA(STEPS_data_client data_client, String delimitador, String algoritmo_SHA, int tempo) throws Exception {

        data_client.data = data_client.udp.receiveUDPclient(tempo);
        if (verbose) {
            System.out.println("PACKET: " + data_client.data);
        }
        long teste = System.currentTimeMillis();
        data_client.tp_A = System.currentTimeMillis();
        if(data_client.data.equals("timeOut")) {
            data_client.erro = "ERRO: Time out (time > " + tempo + " ms)";
            return data_client;
        }else {
            JSONObject packet_1 = new JSONObject(data_client.data);

            String[] quebras_1 = packet_1.getString("encryption").split(delimitador);

            //String packet_1 = "";
            RSA rsa = new RSA("RSA");
            SHA sha = new SHA(algoritmo_SHA);

            int v = Integer.valueOf(quebras_1[0]);
            String packet_aux = "";
            for (int i = 1; i <= v; i++) {
                packet_aux = packet_aux + rsa.decrypt_RSA_E(data_client.keys_rsa_A.getPrivateKey(), quebras_1[i]);
            }

            //String decifragem = rsa.decrypt_RSA_E(data_client.keys_rsa_A.getPrivateKey(), packet_1.getString("encryption"));
            JSONObject packet_2 = new JSONObject(packet_aux);

            //******* Decifrar pacote de Assinatura
            String retorno_hash = rsa.decrypt_RSA_A(data_client.keys_rsa_B.getPublicKey(), packet_2.getString("signature"));

            //******* Hash pacote primeira parte
            String hash = sha.getSHA(packet_2.getString("message"));
            //String values_data = rsa.decrypt_RSA_E(data_client.keys_rsa_A.getPrivateKey(), packet_1);

            if (!retorno_hash.equals(hash)) {
                System.out.println("HASH:\n" + retorno_hash + "\n" + hash);
                data_client.erro = "ERROR: Hash Incorrect (Hash != Hash)";
                return data_client;
            }
            JSONObject message = new JSONObject(packet_2.getString("message"));
            if (!message.getString("nonce_A").equals(data_client.nonce_A)) {
                System.out.println("Nonce A:\n" + message.getString("nonce_A") + "\n" + data_client.nonce_A);
                data_client.erro = "ERROR: Nonce Incorrect (Nonce_A != Nonce_A)";
                return data_client;
            }
            data_client.nonce_B = message.getString("nonce_B");
            BigInteger G = new BigInteger(message.getString("G"), 16);
            BigInteger P = new BigInteger(message.getString("P"), 16);
            data_client.iv_AES = message.getString("iv_AES");
            data_client.dh = new values_DH(P, G, util.Base64S_b(message.getString("DH_B")));
            if (verbose) {
                System.out.println("P = " + data_client.dh.P.toString(16));
                System.out.println("G = " + data_client.dh.G.toString(16));
            }

            teste = System.currentTimeMillis() - teste;
            if (verbose) {
                //util.salvarDadosTxt(teste + "");
                data_client.time_values.add(teste+"");
                System.out.println("step 6 time: " + teste);
            }
        }
        return data_client;
    }

    public STEPS_data_client step_7_client_EC(STEPS_data_client data_client, String algoritmo_SHA, int tempo) throws Exception {
        long teste = System.currentTimeMillis();
        data_client.ecdhe.setSharedSecret(data_client.ecdhe.kp_B.getPublicKey());
        data_client.key_session = data_client.ecdhe.getSharedSecret();
        data_client.seqNumber = data_client.seqNumber + 1;
        data_client.nonce_A = util.getNonce(data_client.ipDest, data_client.ipSource, data_client.seqNumber, algoritmo_SHA);

        //*** PACKET 1 ****
        JSONObject packet1 = new JSONObject();
        String PublicKey_kp_A = util.Base64b_S(data_client.ecdhe.kp_A.getPublicKey().getEncoded());
        packet1.put("PublicKey_kp_A", PublicKey_kp_A);
        packet1.put("nonce_B", data_client.nonce_B);
        packet1.put("nonce_A", data_client.nonce_A);

        String[] algoritmo_SHA1 = algoritmo_SHA.split("-");
        algoritmo_SHA = algoritmo_SHA1[0] + algoritmo_SHA1[1];

        try {
            Signature ecdsa = Signature.getInstance(algoritmo_SHA+"withECDSA");
            ecdsa.initSign(data_client.keys_ecc_A.getPrivateKey());
            String str = packet1.toString();
            byte[] strByte = str.getBytes("UTF-8");
            ecdsa.update(strByte);
            byte[] ass_packet = ecdsa.sign();
            String signature = util.Base64b_S(ass_packet);

            JSONObject packet_2 = new JSONObject();
            packet_2.put("message", packet1);
            packet_2.put("signature", signature);

            if(verbose) {
                System.out.println("Signature: " + signature);
            }
            String encryption = util.encryption_ECIES(data_client.keys_ecc_B.getPublicKey(), packet_2.toString());

            JSONObject packet_send = new JSONObject();
            packet_send.put("encryption", encryption);
            data_client.tp_A = System.currentTimeMillis() - data_client.tp_A;
            packet_send.put("tp_A", data_client.tp_A);

            if (verbose) {
                System.out.println("PACKET: " + packet_send);
            }

            data_client.udp.SendUDPclient(packet_send.toString());

        } catch (NoSuchAlgorithmException | SignatureException | UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 7 time: " + teste);
        }

        return data_client;
    }

    public STEPS_data_client step_7_client_RSA(STEPS_data_client data_client, int tam_ger_dh, String delimitador, String algoritmo_SHA, int tempo) throws Exception {
        long teste = System.currentTimeMillis();
        DH dh = new DH();
        dh.Set_P_G(data_client.dh.P, data_client.dh.G);
        values_DH myPublicKey_2 = dh.generatePublicKey(null, tam_ger_dh, verbose);
        data_client.key_session = dh.computeSharedKey(data_client.dh.myPublicKey);
        data_client.seqNumber = data_client.seqNumber + 1;
        data_client.nonce_A = util.getNonce(data_client.ipDest, data_client.ipSource, data_client.seqNumber, algoritmo_SHA);

        //*** PACKET 1 ****
        String DH_A = util.Base64b_S(myPublicKey_2.myPublicKey);
        JSONObject packet_1 = new JSONObject();
        packet_1.put("DH_A", DH_A);
        packet_1.put("nonce_B", data_client.nonce_B);
        packet_1.put("nonce_A", data_client.nonce_A);

        SHA sha = new SHA(algoritmo_SHA);
        RSA rsa = new RSA("RSA");

        String hash_1 = sha.getSHA(packet_1.toString());
        String ass_packet_1 = rsa.encrypt_RSA_A(data_client.keys_rsa_A.getPrivateKey(), hash_1);

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
            packet_2_enc = packet_2_enc + delimitador + rsa.encrypt_RSA_E(data_client.keys_rsa_B.getPublicKey(), st);

        }

        JSONObject packet_send = new JSONObject();
        packet_send.put("encryption", packet_2_enc);
        data_client.tp_A = System.currentTimeMillis() - data_client.tp_A;
        packet_send.put("tp_A", data_client.tp_A);

        if (verbose) {
            System.out.println("PACKET: " + packet_send);
        }
        data_client.udp.SendUDPclient(packet_send.toString());

        teste = System.currentTimeMillis() - teste;
        if (verbose) {
            //util.salvarDadosTxt(teste + "");
            data_client.time_values.add(teste+"");
            System.out.println("step 7 time: " + teste);
        }
        return data_client;
    }

    public String step_8_client_EC(STEPS_data_client data_client, String modo_AES, String modo_padding, int tam_key, double taxa, int porta) throws Exception {

        int tempo = (int) (data_client.tp_A + data_client.time_network);
        tempo = tempo + (int) (tempo * taxa);
        data_client.data = data_client.udp.receiveUDPclient(tempo);
        long teste = System.currentTimeMillis();
        if (verbose) {
            System.out.println("PACKET: " + data_client.data);
        }
        String key_session1 = "";
        if(data_client.data.equals("timeOut")) {
            System.out.println("ERRO: TimeOut > " + tempo + " ms");
            return null;
        }else {
            JSONObject obj = new JSONObject(data_client.data);

            byte[] key_session = data_client.key_session;
            AES aes = new AES(modo_AES, modo_padding);
            String packet_received = "";
            key_session1 = util.Base64b_S(key_session);
            try {
                packet_received = aes.decrypt_AES((String) obj.get("encryption"), key_session1, tam_key, data_client.iv_AES);
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

            JSONObject packet = new JSONObject(packet_received);

            if (!data_client.nonce_A.equals((String) packet.get("nonce_A"))) {
                System.out.println("ERRO: Nonce incorrect (nonce A != nonce A)");
                System.out.println("NONCE:\n" + data_client.nonce_A + "\n" + packet.get("nonce_A"));
                return null;
            }
            if (!"Ack".equals((String) packet.get("Ack"))) {
                System.out.println("ERRO: Without ACK Packet");
                return null;
            }
            if (verbose) {
                System.out.println("SESSION KEY: " + key_session1);
            }

            teste = System.currentTimeMillis() - teste;
            if (verbose) {
                data_client.time_values.add(teste+"");
                util.write_data_txt(data_client.time_values, "planilha_"+porta);
                System.out.println("step 8 time: " + teste);
            }

            System.out.println("\nTUDO OK!\n");
        }
        return key_session1;

    }

    public String step_8_client_RSA(STEPS_data_client data_client, String delimitador, String modo_AES, String modo_padding, int tam_key, double taxa, int porta) throws Exception {

        int tempo = (int) (data_client.tp_A + data_client.time_network);
        tempo = tempo + (int) (tempo * taxa);
        data_client.data = data_client.udp.receiveUDPclient(tempo);
        long teste = System.currentTimeMillis();
        if (verbose) {
            System.out.println("PACKET: " + data_client.data);
        }
        String key_session1 = "";
        if(data_client.data.equals("timeOut")) {
            System.out.println("ERRO: TimeOut > " + tempo + " ms");
            return null;
        }else{
            JSONObject packet_1 = new JSONObject(data_client.data);
            byte[] key_session = data_client.key_session;
            AES aes = new AES(modo_AES, modo_padding);
            JSONObject packet_received = null;
            key_session1 = util.Base64b_S(key_session);
            try {
                packet_received = new JSONObject(aes.decrypt_AES(packet_1.getString("dados"), key_session1, tam_key, data_client.iv_AES));
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

            if (!data_client.nonce_A.equals(packet_received.getString("nonce_A"))) {
                System.out.println("ERRO: Nonce incorrect (nonce A != nonce A)");
                System.out.println("NONCE:\n" + data_client.nonce_A + "\n" + packet_received.getString("nonce_A"));
                return null;
            }
            if (!"Ack".equals(packet_received.getString("ACK"))) {
                System.out.println("ERRO: Without ACK Packet");
                return null;
            }
            if (verbose) {
                System.out.println("SESSION KEY: " + key_session1);
            }

            teste = System.currentTimeMillis() - teste;
            if (verbose) {
                //util.salvarDadosTxt(teste + "");
                data_client.time_values.add(teste+"");
                util.write_data_txt(data_client.time_values, "planilha_"+porta);
                System.out.println("step 8 time: " + teste);
            }

            System.out.println("\nTUDO OK!\n");
        }
        return key_session1;
    }

    public void step_9_client_send(String key_session, int tam_key, String iv, UDPClient udp, String packet_send) {
        AES aes = new AES();

        try {
            JSONObject obj = new JSONObject();
            obj.put("dados", aes.encrypt_AES(packet_send, key_session, tam_key, iv));
            udp.SendUDPclient(obj.toString());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String step_9_client_received(String key_session, int tam_key, String iv, UDPClient udp, int timeout) {
        AES aes = new AES();
        String data = "";
        try {
            if (timeout == 0) {
                data = udp.receiveUDPclient();
            } else {
                data = udp.receiveUDPclient(timeout);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (!data.equals("timeOut")) {
            JSONObject obj = new JSONObject(data);
            try {
                data = aes.decrypt_AES((String) obj.get("dados"), key_session, tam_key, iv);
            } catch (GeneralSecurityException | IOException ex) {
                System.out.println("ERRO try catch: " + ex.getMessage());
            }
        }
        return data;
    }

}

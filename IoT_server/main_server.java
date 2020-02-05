/**
 * @author Leandro Loffi
 */

public class main_server {

    public static void main(String[] args) {

        int porta = 8655;
        boolean saida = true;


        do {
            IoTAuth_server server = new IoTAuth_server(true);
            server.setciphersuite("DH_RSA_AES128-CBC_SHA512"); // ECDHE_ECDSA_AES128-CBC_SHA512
            server.wait_connect(porta++); // PARALELIZAVEL! //    DH_RSA_AES128-CBC_SHA512
            String p = "";
            do {
                p = server.listen(10000);
                if (!p.equals("timeOut")) {
                    System.out.println(server.getIP() + ":" + server.getPort() + " ::: VALOR: " + p);
                }
                if (p.equals("request")) {
                    // ENVIAR VIA PUBLISH SERVER
                    server.publish_server("Olá sou a resposta do request");
                    server.publish_server("Teste");
                }
            } while (!p.equals("done") && server.is_connected());
            System.out.println("SERVIDOR DESCONECTADO");
        }while(saida);

    }
}
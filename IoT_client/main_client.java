import java.util.Scanner;


/**
 *
 * @author Leandro Loffi
 * FINALIZADO 09/01/2019
 */
public class main_client {

    public static void main(String[] args){
        IoTAuth_client client1 = new IoTAuth_client(true);
        boolean saida = true;
        int aux = 0;
        int porta = 8655;
        do {
            try {
                Thread.sleep(1000);
                do {
                    boolean b = client1.connect("localhost", porta);
                    /*if(client1.isProblem() == true){
                        porta--;
                    }else{
                        porta++;
                    }*/
                    porta = porta + 1;

                } while (!client1.isConnected());
                String ent = "TESTE: "+aux++;
                client1.publish(ent);
                client1.disconnect();
            } catch (Exception e) {
                e.printStackTrace();
            }

            System.out.println("CONTINUAR? (N)");
            Scanner ler = new Scanner(System.in);
            String entrada = ler.next();
            if(entrada.equals("n") || entrada.equals("N")){
                saida = false;
            }

        }while (saida);
    }
}
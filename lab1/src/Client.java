import javax.swing.JFrame;
public class Client // In Client.java from pg. 67 of Dr. Burris Java Cryptography
{
    public static void main(String[] args) throws Exception
    {
        ClientGUI clientGUI = new ClientGUI( );
        clientGUI.setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
        clientGUI.setSize(700,500);
        clientGUI.setVisible(true);
        clientGUI.setLocationRelativeTo(null);
    }
}

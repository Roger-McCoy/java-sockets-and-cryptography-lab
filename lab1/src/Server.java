import javax.swing.*;

public class Server // In Skip.java from pg. 67 of Dr. Burris Java Cryptography
{
    public static void main(String[] args) throws Exception
    {
        ServerGUI serverGUI = new ServerGUI( );
        serverGUI.setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
        serverGUI.setSize(700,500);
        serverGUI.setVisible(true);
        serverGUI.setLocationRelativeTo(null);
    }
}

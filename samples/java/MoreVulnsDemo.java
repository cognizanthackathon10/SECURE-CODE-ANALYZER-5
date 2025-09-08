

import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class MoreVulnsDemo extends HttpServlet {


    private static final String API_KEY = "sk_test_1234567890";


    private java.util.Random rand = new java.util.Random();


    public void runCommand(String userInput) throws IOException {

        String cmd = "ping -c 1 " + userInput;
        Runtime.getRuntime().exec(cmd);
    }

    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file"); 
        File file = new File("/var/www/uploads/" + fileName);

        FileInputStream fis = new FileInputStream(file);
        response.setContentType("text/plain");
        int c;
        while ((c = fis.read()) != -1) {
            response.getWriter().write(c);
        }
        fis.close();
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");

        response.setContentType("text/html");
        response.getWriter().println("<html><body>Hello " + name + "</body></html>");
    }


    public String generateToken() {
        return Long.toHexString(rand.nextLong()); 
    }
}

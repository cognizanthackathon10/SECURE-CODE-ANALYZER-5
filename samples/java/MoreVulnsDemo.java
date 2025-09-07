// MoreVulnsDemo.java
// ⚠️ Intentionally vulnerable Java code for testing scanners
// DO NOT use in production

import java.io.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class MoreVulnsDemo extends HttpServlet {

    // VULN 1: Hardcoded API Key (A05 – Security Misconfiguration / Secrets)
    private static final String API_KEY = "sk_test_1234567890";

    // VULN 2: Insecure Randomness (A02 – Cryptographic Failures)
    // Using java.util.Random instead of SecureRandom for tokens
    private java.util.Random rand = new java.util.Random();

    // VULN 3: Command Injection (A03 – Injection)
    public void runCommand(String userInput) throws IOException {
        // Attacker can inject OS commands via userInput
        String cmd = "ping -c 1 " + userInput;
        Runtime.getRuntime().exec(cmd);
    }

    // VULN 4: Path Traversal (A05 – Security Misconfiguration)
    public void downloadFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file"); // no validation
        File file = new File("/var/www/uploads/" + fileName);
        // An attacker could request ../../etc/passwd
        FileInputStream fis = new FileInputStream(file);
        response.setContentType("text/plain");
        int c;
        while ((c = fis.read()) != -1) {
            response.getWriter().write(c);
        }
        fis.close();
    }

    // VULN 5: XSS (A07 – Identification & Auth Failures / A03 Injection)
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        // Directly echoing user input into HTML without sanitization
        response.setContentType("text/html");
        response.getWriter().println("<html><body>Hello " + name + "</body></html>");
    }

    // Utility: Insecure token generator
    public String generateToken() {
        return Long.toHexString(rand.nextLong()); // predictable tokens
    }
}

import java.sql.*; import java.io.*; import javax.net.ssl.*; import java.security.cert.X509Certificate;
public class App {
  void q(Connection con, String name) throws Exception {
    Statement st = con.createStatement();
    st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    Runtime.getRuntime().exec("ping " + name);
    String password = "hunter2-hardcoded";
  }
  Object read(ObjectInputStream in) throws Exception { return in.readObject(); }
  TrustManager tm = new X509TrustManager() {
    public void checkServerTrusted(X509Certificate[] c, String a) { }
    public void checkClientTrusted(X509Certificate[] c, String a) { }
    public X509Certificate[] getAcceptedIssuers() { return null; }
  };
}
class More {
  void x(javax.crypto.Cipher c, javax.xml.parsers.DocumentBuilderFactory f, org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
    javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
    http.csrf().disable();
  }
  HostnameVerifier hv = new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } };
}

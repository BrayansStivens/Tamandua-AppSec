using System.Data.SqlClient; using System.Diagnostics; using System.Net; using System.Runtime.Serialization.Formatters.Binary;
class App {
  void Q(string name) {
    var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
    Process.Start("cmd.exe", "/c ping " + name);
    var bf = new BinaryFormatter();
    ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
    var h = MD5.Create();
  }
}
class View { string R(string x) { return Html.Raw(x).ToString(); } }

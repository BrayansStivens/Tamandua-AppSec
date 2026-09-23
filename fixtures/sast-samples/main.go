package main
import ("crypto/tls"; "database/sql"; "fmt"; "net/http"; "os"; "os/exec"; "html/template")
func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  name := r.URL.Query().Get("name")
  db.Query("SELECT * FROM users WHERE name = '" + name + "'")
  db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", name))
  exec.Command("sh", "-c", name)
  f, _ := os.Open("/data/" + name); _ = f
  _ = template.HTML(name)
  _ = &tls.Config{InsecureSkipVerify: true}
}
import "crypto/md5"
func weak() { _ = md5.New() }

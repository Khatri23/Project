using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using PasswordLessAuth.Models;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
namespace PasswordLessAuth.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            SqlConnection conn = new SqlConnection("Data Source=(localdb)\\mssqllocaldb;" +
                " Database=ClientDB; Integrated Security=True;");
            SqlCommand cmd = new SqlCommand("Select * from ClientInformation", conn);
            SqlDataAdapter da = new SqlDataAdapter(cmd);
            DataTable dt=new DataTable();
            da.Fill(dt);
            ViewBag.obj = new List<DBContext>();
            for(int i = 0; i < dt.Rows.Count; i++)
            {
                DBContext ctx = new DBContext()
                {
                    public_key_hash = dt.Rows[i][0].ToString(),
                    Public_key_x = dt.Rows[i][1].ToString(),
                    Public_key_y = dt.Rows[i][2].ToString(),
                    Name = dt.Rows[i][3].ToString()
                };
                ViewBag.obj.Add(ctx);
            }
            return View();
        }
        [HttpPost]
        public IActionResult Index(input values)
        {
            SqlConnection conn = new SqlConnection("Data Source=(localdb)\\mssqllocaldb; Database=ClientDB; " +
               "Integrated Security=True");
            SqlCommand cmd = new SqlCommand("Select * from ClientInformation where Id=@a",conn);
            cmd.Parameters.AddWithValue("@a",values.public_key_hash);
            SqlDataAdapter da=new SqlDataAdapter(cmd);
            DataTable dt=new DataTable();
            da.Fill(dt);
            if(dt.Rows.Count <=0)
            {
                return BadRequest("Provided publickey hash is mismatched");
            }
            else
            {
                string msg = values.public_key_hash+values.public_key_x + values.public_key_y;
                if(!PublicKey_Crypto.Verify_Signature(values.public_key_x, values.public_key_y, PublicKey_Crypto.sha256(msg),
                    values.signature_s, values.signature_r))
                    return BadRequest("Signature is invalid wrong information");
            }
            HttpContext.Session.SetString("public_key_hash", values.public_key_hash); //this is session publickey 
            HttpContext.Session.SetString("public_key_x", values.public_key_x);//master publickey is stored in Database
            HttpContext.Session.SetString("public_key_y",values.public_key_y);
            
            return RedirectToAction("Phase2");
        }
        public IActionResult Phase2()
        {
            string private_key = "bbbc72f1cf4fa94c3bca9af8134f8e7ac605760110cb54660a172c9b762fb9a1";
            //focus on sending the challange from the server and deriving the session secret.
            var public_key_x = HttpContext.Session.GetString("public_key_x");
            var public_key_y = HttpContext.Session.GetString("public_key_y");
            var values = PublicKey_Crypto.Server_challange(public_key_x, public_key_y); //0,1 are the hint and 2 is the secret key
            TempData["hint1"] = values[0];
            TempData["hint2"] = values[1];
            
            string msg = HttpContext.Session.GetString("public_key_hash") + values[0] + values[1]+public_key_x+public_key_y; //public_key_hash+hint
            Pair p = PublicKey_Crypto.GeneratePublicKey(private_key);
            public_key_x = Marshal.PtrToStringAnsi(p.first);
            public_key_y = Marshal.PtrToStringAnsi(p.second);
            PublicKey_Crypto.Free_keys(p.first); PublicKey_Crypto.Free_keys(p.second);
            TempData["Public_Key_x"] = public_key_x;
            TempData["Public_Key_y"] = public_key_y;
            p =PublicKey_Crypto.GenerateSignature(private_key, PublicKey_Crypto.sha256(msg));
            TempData["s"]=Marshal.PtrToStringAnsi(p.first);
            TempData["r"]=Marshal.PtrToStringAnsi(p.second);
            PublicKey_Crypto.Free_keys(p.first); PublicKey_Crypto.Free_keys(p.second);
            HttpContext.Session.SetString("secret", values[2]);
            
            TempData["Phash"] = HttpContext.Session.GetString("public_key_hash");
            return View();
        }
        [HttpPost]
        public IActionResult Phase2(input i)
        {
            string private_key = "bbbc72f1cf4fa94c3bca9af8134f8e7ac605760110cb54660a172c9b762fb9a1";
            string n1 = Marshal.PtrToStringAnsi(PublicKey_Crypto.Response(HttpContext.Session.GetString("public_key_x"),
                HttpContext.Session.GetString("public_key_y"), private_key));
            string id = HttpContext.Session.GetString("public_key_hash");
            //signature verify:
            string secret = HttpContext.Session.GetString("secret");
            string nonce = PublicKey_Crypto.HMAC(PublicKey_Crypto.HMAC(
               id, secret), n1);
            Console.WriteLine("nonce: " + nonce);
            Console.WriteLine("Secret for nonce: " + n1);
            Console.WriteLine("pre shared Secret: " + secret);
            PublicKey_Crypto.PRF(secret, "4b65792045786368616e6765", nonce);
            string msg =id + nonce;
            msg=PublicKey_Crypto.sha256(msg);
            SqlConnection conn = new SqlConnection("Data Source=(localdb)\\mssqllocaldb; Database=ClientDB; " +
              "Integrated Security=True");
            SqlCommand cmd = new SqlCommand("Select * from ClientInformation where Id=@a", conn);
            cmd.Parameters.AddWithValue("@a", id);
            SqlDataAdapter da = new SqlDataAdapter(cmd);
            DataTable dt = new DataTable();
            da.Fill(dt);
            if (dt.Rows.Count <= 0)
            {
                return BadRequest("Provided publickey hash is mismatched");
            }
            else
            {
                DBContext db = new DBContext() {
                    public_key_hash = dt.Rows[0][0].ToString(),
                    Public_key_x = dt.Rows[0][1].ToString(),
                    Public_key_y = dt.Rows[0][2].ToString(),
                    Name = dt.Rows[0][3].ToString()
                };
                if (!PublicKey_Crypto.Verify_Signature(db.Public_key_x, db.Public_key_y, msg, i.signature_s, i.signature_r))
                    return BadRequest("Invalid signature!");
                return View("Page", db);
            }
        }
        public IActionResult Page(DBContext db)
        {
            return View(db);
        }
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Register(DBContext ctx)
        {
            ctx.public_key_hash = PublicKey_Crypto.Checksum(ctx.Public_key_x, ctx.Public_key_y);
            return RedirectToAction("InsertDB", ctx);   
        }
        public IActionResult InsertDB(DBContext ctx)
        {
            return View(ctx);
        }
        [HttpPost]
        public IActionResult InsertDB(DBContext ctx,bool stat)
        {
            if (ctx == null)
                return BadRequest("Model was null");
            SqlConnection conn = new SqlConnection("Data Source=(localdb)\\mssqllocaldb; Database=ClientDB; " +
                "Integrated Security=True");
            SqlCommand cmd = new SqlCommand(
            "INSERT INTO ClientInformation VALUES (@a, @b, @c, @d)", conn);
            cmd.Parameters.AddWithValue("@a", ctx.public_key_hash);
            cmd.Parameters.AddWithValue("@b", ctx.Public_key_x);
            cmd.Parameters.AddWithValue("@c", ctx.Public_key_y);
            cmd.Parameters.AddWithValue("@d", ctx.Name);
            conn.Open();
            cmd.ExecuteNonQuery();
            conn.Close();
            return RedirectToAction("Index");
        }
    }
}

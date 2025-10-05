using System.ComponentModel.DataAnnotations;

namespace PasswordLessAuth.Models
{
    public class DBContext
    {
        [Required(ErrorMessage ="Name is required")]
        public string Name {  get; set; }
        [Required(ErrorMessage ="Publickey is required")] public string Public_key_x {  get; set; }
        [Required(ErrorMessage ="Publickey is required")] public string Public_key_y { get; set; }
         public string public_key_hash { get; set; }
        
    }
}

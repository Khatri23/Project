
using System.ComponentModel.DataAnnotations;

namespace PasswordLessAuth.Models
{
    public class input
    {
        [Required]
        public string public_key_hash {  get; set; }
        [Required] public string public_key_x {  get; set; }
        [Required] public string public_key_y { get; set; }
        [Required] public string signature_s {  get; set; }
        [Required] public string signature_r { get; set; }
    }
}

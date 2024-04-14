using Microsoft.AspNetCore.Identity;

namespace AuthenticationAuthorisation.Models
{
    public class AppUser : IdentityUser
    {
        public String FullName { get; set; }

    }
}
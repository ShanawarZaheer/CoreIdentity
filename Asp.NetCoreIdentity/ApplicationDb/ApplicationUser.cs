using Microsoft.AspNetCore.Identity;

namespace Asp.NetCoreIdentity.ApplicationDb
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}

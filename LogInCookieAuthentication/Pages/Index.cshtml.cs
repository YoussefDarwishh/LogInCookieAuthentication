using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace LogInCookieAuthentication.Pages;

public class IndexModel : PageModel
{
    [BindProperty]
    public LoginInput LoginInput { get; set; }

    public bool IsLoggedIn { get; private set; }

    public void OnGet()
    {
        IsLoggedIn = User.Identity?.IsAuthenticated ?? false;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        string username = LoginInput.Username;
        string password = LoginInput.Password;

        if (username == "intern" && password == "summer 2023 july")
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "Intern")
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties();
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

            IsLoggedIn = true;

            return RedirectToPage();
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Invalid credentials");
            IsLoggedIn = false;
            return Page();
        }
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToPage();
    }
}

public class LoginInput
{
    [Required]
    public string Username { get; set; }
    [Required]
    public string Password { get; set; }
}

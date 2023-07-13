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
    public string Username { get; set; }

    [BindProperty]
    [DataType(DataType.Password)]
    public string Password { get; set; }
    public bool IsLoggedIn { get; private set; }
    public string ErrorMessage { get; private set; }

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

        if (Username == "intern" && Password == "summer 2023 july")
        {
            var claims = new List<Claim>
            {
            new Claim(ClaimTypes.Name, Username),
            new Claim(ClaimTypes.Role, "Intern")
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties();
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

            IsLoggedIn = true;
            ErrorMessage = null;

            return RedirectToPage();
        }
        else
        {
            ErrorMessage = "Invalid credentials";
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
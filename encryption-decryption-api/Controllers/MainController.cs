using encryption_decryption_api.Model;
using encryption_decryption_api.Services;
using Microsoft.AspNetCore.Mvc;

namespace encryption_decryption_api.Controllers;

[Route("api/[controller]")]
[ApiController]
public class MainController : ControllerBase
{
    [HttpGet]
    public string Get()
    {
        return "Successfully reached - Security Api -  https://mertcanduldul.vercel.app";
    }


    [HttpPost]
    [Route("encrypt")]
    public async Task<IActionResult> Encrypt(MainDto request)
    {
        StenographService stenographService = new StenographService();
        MainDto response = new MainDto();
        response = request;
        var result = stenographService.EncryptString(request.Text, request.SecretKey);
        response.ResponseText = result;
        if(String.IsNullOrEmpty(request.SecretKey))
            response.SecretKey = "I can not show you the secret key because you did not enter it.";
        return Ok(response);
    }

    [HttpPost]
    [Route("decrypt")]
    public async Task<IActionResult> Decrypt(MainDto request)
    {
        StenographService stenographService = new StenographService();
        MainDto response = new MainDto();
        response = request;
        var result = stenographService.DecryptString(request.Text, request.SecretKey);
        response.ResponseText = result;
        return Ok(response);
    }
}
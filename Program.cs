using AuthenticationAuthorisation.Configuration;
using AuthenticationAuthorisation.Data;
using AuthenticationAuthorisation.Models;
using AuthenticationAuthorisation.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;


var builder = WebApplication.CreateBuilder(args);
SQLitePCL.Batteries.Init();

// Add services to the container.
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=auth.db"));
builder.Services.AddIdentity<AppUser, IdentityRole>().AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// Register the AccountService and RolesService
builder.Services.AddScoped<AccountService>();
builder.Services.AddScoped<RolesService>();

// Register JwtConfiguration
builder.Services.AddSingleton<JwtConfiguration>();

// Add authorization services
builder.Services.AddAuthorization();

// Add controller services
builder.Services.AddControllers();

// Configure JWT authentication using JwtConfiguration
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Retrieve JwtConfiguration from the service provider
#pragma warning disable ASP0000 // Do not call 'IServiceCollection.BuildServiceProvider' in 'ConfigureServices'
        var jwtConfig = builder.Services.BuildServiceProvider().GetRequiredService<JwtConfiguration>();
#pragma warning restore ASP0000 // Do not call 'IServiceCollection.BuildServiceProvider' in 'ConfigureServices'
        jwtConfig.ConfigureJwtBearerOptions(options);
    });

// Add Swagger services using SwaggerConfig
builder.Services.AddSwaggerGen(SwaggerConfig.AddSwagger);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API v1"));
}
app.UseHttpsRedirection();
app.UseCors(options =>
{
    options.AllowAnyHeader();
    options.AllowAnyMethod();
    options.AllowAnyOrigin();
});
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

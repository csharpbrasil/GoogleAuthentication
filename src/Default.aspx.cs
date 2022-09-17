using System;

namespace GoogleAuthentication
{
    public partial class _Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                Session.Remove("Secret");
                Session.Remove("Identity");
            }
        }
        
        protected void btnSalvar_Click(object sender, EventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(txtIdentity.Text))
            {
                var secret = txtSecret.Text;
                var identity = txtIdentity.Text;

                var gauth = new GAuthenticator(identity, "csharpbrasil.com.br", secret);
                imgQRCode.ImageUrl = gauth.QRCodeUrl;
                imgQRCode.DataBind();

                Panel1.Visible = true;

                Session.Add("SecretByte", gauth.Secret);
                Session.Add("Identity", identity);
            }
        }

        protected void btnTestar_Click(object sender, EventArgs e)
        {
            Response.Redirect("auth.aspx");
        }
    }
}
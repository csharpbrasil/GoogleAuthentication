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
            if (txtIdentity.Text.Length > 0)
            {
                string secret = txtSecret.Text;
                string identity = txtIdentity.Text;

                GAuthenticator gauth = new GAuthenticator();
                gauth.QRCodeSize = 200;
                gauth.Identity = identity;
                gauth.Issuer = "www.csharpbrasil.com.br";
                gauth.setSecretKey(secret);

                imgQRCode.ImageUrl = gauth.QRCodeUrl;
                imgQRCode.DataBind();

                Panel1.Visible = true;
            }
        }

        protected void btnTestar_Click(object sender, EventArgs e)
        {
            string secret = txtSecret.Text;
            string identity = txtIdentity.Text;
            byte[] secretByte = new System.Text.ASCIIEncoding().GetBytes(secret);

            Session.Add("Secret", secret);
            Session.Add("SecretByte", secretByte);
            Session.Add("Identity", identity);
            Response.Redirect("auth.aspx");
        }
    }
}
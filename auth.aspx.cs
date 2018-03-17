using System;

namespace GoogleAuthentication
{
    public partial class auth : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        protected void btnOK_Click(object sender, EventArgs e)
        {
            string secret = (string)Session["Secret"];
            string identity = (string)Session["Identity"];
            byte[] secretByte = (byte[])Session["SecretByte"];

            GAuthenticator gauth = new GAuthenticator();
            gauth.Secret = secretByte;
            gauth.Identity = identity;

            int code;
            int.TryParse(txtCodigo.Text, out code);

            if (gauth.OneTimePassword == code)
            {
                ltlResult.Text = "Sucesso! Codigo correto!";
            }
            else
            {
                ltlResult.Text = "Erro! Codigo incorreto!";
            }
        }

        protected void btnVoltar_Click(object sender, EventArgs e)
        {
            Session.Remove("Secret");
            Session.Remove("SecretByte");
            Session.Remove("Identity");
            Response.Redirect("Default.aspx");
        }
    }
}
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
            var identity = (string)Session["Identity"];
            var secretByte = (byte[])Session["SecretByte"];
            int.TryParse(txtCodigo.Text, out int code);

            var gauth = new GAuthenticator(identity, secretByte);

            ltlResult.Text = gauth.OneTimePassword == code ? "Sucesso! Codigo correto!" : "Erro! Codigo incorreto!";
        }

        protected void btnVoltar_Click(object sender, EventArgs e)
        {
            Session.Remove("SecretByte");
            Session.Remove("Identity");
            Response.Redirect("Default.aspx");
        }
    }
}
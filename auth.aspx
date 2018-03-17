<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="auth.aspx.cs" Inherits="GoogleAuthentication.auth" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <label>Informe: </label>
        <asp:TextBox ID="txtCodigo" runat="server"></asp:TextBox> <asp:Button ID="btnOK" runat="server" Text="OK" OnClick="btnOK_Click" /><asp:Button ID="btnVoltar" runat="server" Text="<< Voltar" OnClick="btnVoltar_Click" />
        <br />
        <asp:Literal ID="ltlResult" runat="server"></asp:Literal>
    </div>
    </form>
</body>
</html>

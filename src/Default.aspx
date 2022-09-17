<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="GoogleAuthentication._Default" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
    <style type="text/css">
        label {
            width: 150px;
            display: inline-block;
            border: 1px solid #ccc;
        }
    </style>
</head>
<body>
    <form id="form1" runat="server">
        <div id="geral">
            <label>Chave: </label><asp:TextBox ID="txtSecret" runat="server" Width="200px" /><br />
            <label>Identificação: </label><asp:TextBox ID="txtIdentity" runat="server" Width="200px" /><br />

            <asp:Panel ID="Panel1" runat="server" Visible="false">
                <asp:Image ID="imgQRCode" runat="server" /><br />
            </asp:Panel>
            <br />
            <asp:Button ID="btnSalvar" runat="server" Text="Salvar" OnClick="btnSalvar_Click" />
            <asp:Button ID="btnTestar" runat="server" Text="Testar &gt;&gt;" OnClick="btnTestar_Click" />
        </div>
    </form>
</body>
</html>

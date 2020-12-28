using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace RIoT
{
    class HttpsListener
    {

        static internal void StartListener(string _serverCert, string _serverKey, string serverCA, string _clientCert, string _clientKey)
        {
            // note that the programmatic cert creation and installation didn't work so did this - 
            // makecert.exe - r - a sha1 - n CN = localhost - sky exchange - pe - b 01 / 01 / 2000 - e 01 / 01 / 2050 - ss my
            // then this
            // C:\Repos\RIoT Development\Utlilities\RIoTUtils\bin\Debug\Certs>netsh http add sslcert ipport=0.0.0.0:5556 appid={20a30499-7f02-446f-8716-e85fcdbb0ce4} certhash=360e6b474436076ff6cca4b1281fda021c276dbb
            // SSL Certificate successfully added



            // we need to add the server cert to the store for HttpListener to use it
            string serverPfxFile = "ServerCert.PFX";
            Helpers.MakePFXFile(_serverCert, _serverKey, serverPfxFile, null);
            Helpers.DeleteCertsByIssuer("MSR_TEST");

            Helpers.InstallCert(serverCA);
            Helpers.InstallCert(serverPfxFile);
            Helpers.SetCertForPort(serverPfxFile, 5556);

            string clientPfxFile = "ClientCert.PFX";
            Helpers.MakePFXFile(_clientCert, _clientKey, clientPfxFile, null);



            // ‎9970e392d44f8d08c158660f1a0b05838f6201f0

            // ‎360e6b474436076ff6cca4b1281fda021c276dbb
            SSLValidator.OverrideValidation();

            var listener = new HttpListener();
            
            listener.Prefixes.Add("https://127.0.0.1:5556/ABC/");
            listener.Start();
            Console.WriteLine("Listening...");


            SslTcpClient.RunClient(_clientCert, _clientKey);

            /*
            // make a request
            //You must change the path to point to your .cer file location. 
            X509Certificate Cert = X509Certificate.CreateFromCertFile("ClientCert.PFX");
            // Handle any certificate errors on the certificate from the server.
            // You must change the URL to point to your Web server.
            HttpWebRequest Request = (HttpWebRequest)WebRequest.Create("https://127.0.0.1:5556/ABC/123");
            Request.ClientCertificates.Add(Cert);
            Request.UserAgent = "Client Cert Sample";
            Request.Method = "GET";
            var responseFromServer = Request.GetResponseAsync();
            //string respx = responseFromServer.Result.ToString();

    */
            
            var context = listener.GetContext();
            HttpListenerRequest request = context.Request;
            // Obtain a response object.
            HttpListenerResponse response = context.Response;

            var cert = request.GetClientCertificate();

            // Construct a response.
            string responseString = "<HTML><BODY> Hello world!</BODY></HTML>";
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            // Get a response stream and write the response to it.
            response.ContentLength64 = buffer.Length;
            System.IO.Stream output = response.OutputStream;
            output.Write(buffer, 0, buffer.Length);
            // You must close the output stream.
            output.Close();
            listener.Stop();


        }
    }
    public static class SSLValidator
    {
        private static RemoteCertificateValidationCallback _orgCallback;

        private static bool OnValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        public static void OverrideValidation()
        {
            _orgCallback = ServicePointManager.ServerCertificateValidationCallback;
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(OnValidateCertificate);
            ServicePointManager.Expect100Continue = true;
        }

        public static void RestoreValidation()
        {
            ServicePointManager.ServerCertificateValidationCallback = _orgCallback;
        }
    }
}

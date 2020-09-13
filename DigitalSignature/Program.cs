using CommandLine;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace DigitalSignature
{
    public class Options
    {
        [Option("signCert", HelpText = "Set certificate path.", Required = true)]
        public string SignatureCertificate { get; set; }

        [Option("signName", HelpText = "Set signature name.", Required = true)]
        public string SignatureName { get; set; }

        [Option("signPass", HelpText = "Set certificate password.", Required = true)]
        public string SignaturePassword { get; set; }

        [Option("signRecHeight", HelpText = "Set signature rectangle height.", Required = true)]
        public int SignatureRectangleHeight { get; set; }

        [Option("signRecWidth", HelpText = "Set signature rectangle width.", Required = true)]
        public int SignatureRectangleWidth { get; set; }

        [Option("signRecX", HelpText = "Set signature rectangle x position.", Required = true)]
        public int SignatureRectangleX { get; set; }

        [Option("signRecY", HelpText = "Set signature rectangle y position.", Required = true)]
        public int SignatureRectangleY { get; set; }

        [Option("signText", HelpText = "Set signature text.", Required = true)]
        public string SignatureText { get; set; }

        [Option("srcPdf", HelpText = "Set pdf file to sign.", Required = true)]
        public string SrcPdf { get; set; }
    }

    static class Program
    {
        static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(options =>
            {
                string keystore = options.SignatureCertificate;
                char[] password = options.SignaturePassword.ToCharArray();

                Pkcs12Store pkcs12Store = new Pkcs12Store(new FileStream(keystore, FileMode.Open, FileAccess.Read), password);
                string keyAlias = null;

                foreach (object alias in pkcs12Store.Aliases)
                {
                    keyAlias = (string)alias;

                    if (pkcs12Store.IsKeyEntry(keyAlias))
                    {
                        break;
                    }
                }

                ICipherParameters key = pkcs12Store.GetKey(keyAlias).Key;

                X509CertificateEntry[] certificateEntry = pkcs12Store.GetCertificateChain(keyAlias);
                X509Certificate[] certificate = new X509Certificate[certificateEntry.Length];

                for (int i = 0; i < certificateEntry.Length; ++i)
                {
                    certificate[i] = certificateEntry[i].Certificate;
                }

                string srcPdf = options.SrcPdf;
                string destPdf = System.IO.Path.GetTempFileName();

                PdfReader pdfReader = new PdfReader(srcPdf);
                PdfSigner pdfSigner = new PdfSigner(pdfReader, new FileStream(destPdf, FileMode.Create), new StampingProperties());

                PdfSignatureAppearance appearance = pdfSigner.GetSignatureAppearance();

                appearance
                    .SetLayer2Text(options.SignatureText)
                    .SetPageRect(new Rectangle(options.SignatureRectangleX, options.SignatureRectangleY, options.SignatureRectangleWidth, options.SignatureRectangleHeight))
                    .SetPageNumber(1);

                pdfSigner.SetFieldName(options.SignatureName);

                IExternalSignature privateKeySignature = new PrivateKeySignature(key, DigestAlgorithms.SHA256);

                pdfSigner.SignDetached(privateKeySignature, certificate, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

                Console.WriteLine(destPdf);
            });
        }
    }

}

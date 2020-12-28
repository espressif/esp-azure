/*
 * Microsoft Copyright, 2017
 * Author: pengland
 */
namespace DICETest
{
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Checks a chain using the system (rather than bouncy castle) chain validator.  BC seems to have
    /// problems with EKU - clientAuth
    /// </summary>
    class ChainChecker
    {
        public static bool CheckChain(Org.BouncyCastle.X509.X509Certificate[] certs)
        {
            int numCerts = certs.Length;
            var sysCerts = new System.Security.Cryptography.X509Certificates.X509Certificate2[numCerts];
            for(int j=0;j<certs.Length;j++)
            {
                sysCerts[j] = new System.Security.Cryptography.X509Certificates.X509Certificate2(certs[j].GetEncoded());
            }

            X509Chain chain = new X509Chain(false);

            // todo: this seems like a reasonable starting point for the flags
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Note: this flag seems to be ignored.  In any case, we don't use the 
            // machine or user-context cert store: we check the root against DeviceCA
            // provided as a parameter during class instantiation (or a database of authorized
            // CAs in the final service.)
            chain.ChainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;

            // Add the intermediate and root-CA certs to the ExtraStore
            for (int j=1;j<numCerts;j++)
            {
                chain.ChainPolicy.ExtraStore.Add(sysCerts[j]);
            }

            // Can we build a chain using the leaf/alias cert?
            bool valid = chain.Build(sysCerts[0]);
            if (!valid)
            {
                Program.Print($"Chain building failed.  Errors are:", NotifyType.Error);
                foreach (var err in chain.ChainStatus)
                {
                    // the UnstrustedRoot error does not indicate a problem with the chain, but instead the fact that 
                    // the root is not in the system/user store (if the only error is UntrustedRoot, then Build() succeeds.)
                    if (err.Status == X509ChainStatusFlags.UntrustedRoot) continue;
                    Program.Print($"        Error:{err.Status.ToString()}", NotifyType.Error);
                }
                return false;
            }

            return true;
        }
    }
}

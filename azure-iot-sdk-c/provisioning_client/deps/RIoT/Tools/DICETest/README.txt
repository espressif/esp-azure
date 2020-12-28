
DICETest is a command-line tool for doing basic validation of the certificates 
produced by a DICE/RIoT implementation.

Example usage:

// Check the validity of various certificate chains
DICETest -chain AliasCert.PEM DeviceIDCert.PEM RootCert.PEM
DICETest -chain AliasCert.PEM DeviceIDCert.PEM IntermediateCert.PEM RootCert.PEM
DICETest -chain AliasCert.PEM DeviceIDSelfSignedCert.PEM

// Check a "proof of posession" DeviceID certificate for the given root cert
DICETest -pop CN=XXXXyyyyZZZZ DevIDPopCert.PEM RootCert.PEM

// Check that the CSR is valid (self-signed)
DICETest -csr DevIDCSR.PEM


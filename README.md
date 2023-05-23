# P7 Bundler Instructions

## Purpose

Remove reliance on NSS and OpenSSL for bundling certificates into a PKCS7 for use in disseminate DoD, JITC, WCF, type certificates in easy zip files.

## Steps To Create A Bundle

1) Get a copy of p7certsign.exe, either by compiling this source code or from a PKE developer.

2) Have a folder in the same directory as p7certsign.exe labeled `certificates`.

3) Within that `certificates` folder have more nested folders, each one corresponding to the bundle you want to create.

4) Within each named folder will be files ending in the .cer extension.  They can be either DER or PEM format.
<br>    i.e.
<br>        certificates/
<br>        ├── DoD
<br>        │   ├── DOD_EMAIL_CA-72.cer
<br>        │   ├── DOD_EMAIL_CA-73.cer
<br>        │   ├── DOD_ID_CA-72.cer
<br>        │   ├── DOD_ID_CA-73.cer
<br>        │   └── DoD_Root_CA_6.cer
<br>        ├── ECA
<br>        │   ├── ECA_Root_CA_4.cer
<br>        │   ├── IdenTrust_ECA_Component_S23.cer
<br>        │   ├── IdenTrust_ECA_S23.cer
<br>        │   ├── WidePoint_ECA_8.cer
<br>        │   └── WidePoint_ORC_ECA_7.cer
<br>        ├── Gray
<br>        │   ├── DoD_Gray_PKI_Subordinate_CA_1.cer
<br>        │   ├── DoD_Gray_PKI_Subordinate_CA_2.cer
<br>        │   └── USG_Gray_PKI_Root_CA_1.cer
5) Double click the p7certsign.exe file to run the program.  It will loop through the certificates 
folders nested directories to find any bundles that need to be run.

6) The program will first have you select a signing certificate that signs the hash file, then 
it will prompt you for the version number of each bundle to be run.

7) For each bundle you run through, you will enter your PIN once to sign the sha256 file and a 
zip will be created that matches the folder name and version number you input.

8) The output will be put in the same location of the .exe file as a .zip file for each bundle.

## What's In The zip

Each bundle contains files that help verify the contents of the zip file you are given.  Here is a breakdown of the each file:

* certificates_pkcs7_v[version_number]_[group_name].sha256

    This is a signed pkcs7 message with the sha256 hashes of all files contained in the zip.

* certificates_pkcs7_v[version_number]_[group_name]_der.p7b

    This file contains every certificate that was in the bundle folder, all grouped together in one p7b.

* certificates_pkcs7_v[version_number]\_[group_name]\_[root_ca_name]_der.p7b

    This file(s) contain every certificate that was issued by the Root CA at the tail end of the file name. 
    If a user only wants certs from a certain root, they can use these files to isolate that CA.

* dod_pke_chain.pem

    A chain of certificates that is used to verify the signer of the bundle.

* README.txt

    Instuctions on how to verify the signer of the bundle and it's contents.

## Example Output

Double clicking on the p7certsign.exe file with the example certificates in step four from above yields this output. 
In this example I chose to run the DoD bundle with version 5_9, skip the ECA bundle, and enter some improper input for the
version number of the Gray bundle.  It will reprompt you for the proper format and continue.

```cmd
Run bundle for DoD? ([Y]es/[N]o/[Q]uit)
y
What bundle number would for this bundle?  i.e. 5_2 or 1_2_345
5_9

Successfully added cert with Subject: DOD EMAIL CA-72 and
Issuer: DoD Root CA 6 to the DoD bundle.

Successfully added cert with Subject: DOD EMAIL CA-73 and
Issuer: DoD Root CA 6 to the DoD bundle.

Successfully added cert with Subject: DOD ID CA-72 and
Issuer: DoD Root CA 6 to the DoD bundle.

Successfully added cert with Subject: DOD ID CA-73 and
Issuer: DoD Root CA 6 to the DoD bundle.

Successfully added cert with Subject: DoD Root CA 6 and
Issuer: DoD Root CA 6 to the DoD bundle.

***** Signing certificates_pkcs7_v5_9_dod using Windows CryptSignMessage function *****
Run bundle for ECA? ([Y]es/[N]o/[Q]uit)
n
Run bundle for Gray? ([Y]es/[N]o/[Q]uit)
y
What bundle number would for this bundle?  i.e. 5_2 or 1_2_345
12354_asdfb
Error with input, must be at least two numbers seperated by an underscore.
12354_45321

Successfully added cert with Subject: DoD Gray PKI Subordinate CA 1 and
Issuer: USG Gray PKI Root CA 1 to the Gray bundle.

Successfully added cert with Subject: DoD Gray PKI Subordinate CA 2 and
Issuer: USG Gray PKI Root CA 1 to the Gray bundle.

Successfully added cert with Subject: USG Gray PKI Root CA 1 and
Issuer: USG Gray PKI Root CA 1 to the Gray bundle.

***** Signing certificates_pkcs7_v12354_45321_gray using Windows CryptSignMessage function *****
```

This output two zip files and this was their contents:

certificates_pkcs7_v5_9_dod.zip:

```bash
$ tree -sh certificates_pkcs7_v5_9_dod
[   0]  certificates_pkcs7_v5_9_dod
├── [4.3K]  README.txt
├── [3.2K]  certificates_pkcs7_v5_9_dod.sha256
├── [7.2K]  certificates_pkcs7_v5_9_dod_DoD_Root_CA_6_der.p7b
├── [7.2K]  certificates_pkcs7_v5_9_dod_der.p7b
└── [1.2K]  dod_pke_chain.pem
```

certificates_pkcs7_v12354_45321_gray.zip:

```bash
$ tree -sh certificates_pkcs7_v12354_45321_gray
[   0]  certificates_pkcs7_v12354_45321_gray
├── [4.4K]  README.txt
├── [3.2K]  certificates_pkcs7_v12354_45321_gray.sha256
├── [2.2K]  certificates_pkcs7_v12354_45321_gray_USG_Gray_PKI_Root_CA_1_der.p7b
├── [2.2K]  certificates_pkcs7_v12354_45321_gray_der.p7b
└── [1.2K]  dod_pke_chain.pem
```
#![allow(unused_imports)]
#![allow(unused_mut)]
use std::path::Path;
use std::{
    collections::HashMap,
    ffi::{c_void, OsStr},
    fs::{DirEntry, File},
    io::Write,
    mem::transmute,
    path::Component,
};
use walkdir::WalkDir;
use windows::{
    core::*,
    Win32::{
        Foundation::GetLastError,
        Security::Cryptography::{
            CertAddCertificateContextToStore, CertAddStoreToCollection, CertCloseStore,
            CertCreateCertificateContext, CertFreeCertificateChain, CertFreeCertificateContext,
            CertOpenStore, CertSaveStore, CryptBinaryToStringA, CryptSignMessage,
            CryptStringToBinaryA, CryptStringToBinaryW, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
            CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
            CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_CERTIFICATE_CONTEXT,
            CERT_STORE_PROV_COLLECTION, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W,
            CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_FILENAME_A, CERT_STORE_SAVE_TO_FILENAME_W,
            CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
            CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB, CRYPT_SIGN_MESSAGE_PARA,
            CRYPT_STRING_BASE64HEADER, HCERTSTORE, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING,
            UI::{self, CERT_SELECT_STRUCT_W, CSS_ENABLETEMPLATE},
            X509_ASN_ENCODING,
        },
        Storage::FileSystem::{
            CreateFileW, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_WRITE,
        },
        System::{
            LibraryLoader::{FreeLibrary, GetProcAddress, LoadLibraryW},
            Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY},
        },
    },
};

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions
type CertSelectCertificateW = extern "stdcall" fn(*const CERT_SELECT_STRUCT_W);

fn main() -> Result<()> {
    unsafe {
        let mut fresh_cert: *mut CERT_CONTEXT = ::core::mem::zeroed();
        select_signing_cert(&mut fresh_cert)?;
        let mut bundles: HashMap<String, HCERTSTORE> = HashMap::new();
        let mut current_dir_string: String;
        if std::fs::metadata("current_build").is_err() {
            std::fs::create_dir("current_build").unwrap();
        }
        let mut readme_string: String =
            String::from_utf8_lossy(include_bytes!("readme_template.txt")).into();
        readme_string = readme_string.replace("IRFILENAME", "new_file_name");
        readme_string = readme_string.replace("SIGNINGCHAIN", "dod_pke_chain.pem");
        std::fs::write("current_build/README.txt", readme_string.as_bytes()).unwrap();

        for entry in WalkDir::new("certificates")
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().is_dir() && entry.path().parent().ne(&Some(Path::new(""))) {
                current_dir_string = entry
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let mut temp_store = CertOpenStore(
                    CERT_STORE_PROV_MEMORY,
                    CERT_QUERY_ENCODING_TYPE::default(),
                    HCRYPTPROV_LEGACY::default(),
                    CERT_OPEN_STORE_FLAGS(0),
                    ::core::mem::zeroed(),
                )?;
                bundles.insert(current_dir_string.clone(), temp_store);

                for certificate_file in entry.path().read_dir().expect("read_dir call failure") {
                    let current_file = certificate_file.unwrap().path();
                    if current_file.is_file() && current_file.extension().unwrap() == "cer" {
                        let cert_context =
                            get_context_cert_file(&std::fs::read(current_file).unwrap())?;
                        let update_store = bundles.get(&current_dir_string).unwrap();
                        let test_add = CertAddCertificateContextToStore(
                            *update_store,
                            cert_context,
                            CERT_STORE_ADD_REPLACE_EXISTING,
                            None,
                        );

                        if test_add.as_bool() {
                            //println!("Successfully added a component to {}", &current_dir_string);
                        }
                    }
                }
            }
        }

        let mut collection_store = CertOpenStore(
            CERT_STORE_PROV_COLLECTION,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS(0),
            ::core::mem::zeroed(),
        )?;
        for y in bundles.into_iter() {
            let mut file_name = "current_build/certificates_pkcs7_5_12_".to_owned();
            file_name.push_str(y.0.as_str());
            file_name.push_str(".p7b\0");

            CertAddStoreToCollection(collection_store, y.1, 0, 0);

            // create individual files for each bundle
            /* let file_name_ptr = PCSTR(file_name.as_ptr()).as_ptr();
            CertSaveStore(
                y.1,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                CERT_STORE_SAVE_AS_PKCS7,
                CERT_STORE_SAVE_TO_FILENAME_A,
                file_name_ptr as _,
                0,
            ); */

            if !CertCloseStore(y.1, 0).as_bool() {
                println!("Failed to close the {} memory_store", y.0);
            }
        }
        let collection_name = s!("current_build/collection.p7b");
        CertSaveStore(
            collection_store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_FILENAME_A,
            collection_name.as_ptr() as _,
            0,
        );

        //do_the_signing(fresh_cert);
        let mut zipper = std::fs::File::create("zip_zopp.zip").unwrap();
        let mut zip = zip::ZipWriter::new(zipper);
        let zip_options = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        

        for entry in WalkDir::new("current_build")
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().is_file() {
                let current_file = entry.path().file_name().unwrap().to_str().unwrap();
                //dbg!(current_file);
                //dbg!(&entry);
                zip.start_file(current_file, zip_options).unwrap();
                zip.write_all(&std::fs::read(entry.path().to_str().unwrap()).unwrap()).unwrap();
            }
        }

        zip.finish().unwrap();

        if !CertFreeCertificateContext(Some(fresh_cert)).as_bool() {
            println!("Failed to close fresh_cert");
        }
    }
    Ok(())
}

pub unsafe fn select_signing_cert(fresh_cert: *mut *mut CERT_CONTEXT) -> Result<()> {
    let store_name = w!("My").as_ptr() as *const c_void;

    let mut personal_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        CERT_QUERY_ENCODING_TYPE::default(),
        HCRYPTPROV_LEGACY::default(),
        CERT_OPEN_STORE_FLAGS(
            CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
        ),
        Some(store_name),
    )?;

    let crypt_ui_instance = LoadLibraryW(w!("cryptdlg.dll"))?;

    let cert_select_struct = CERT_SELECT_STRUCT_W {
        dwSize: std::mem::size_of::<CERT_SELECT_STRUCT_W>() as u32,
        hwndParent: ::core::mem::zeroed(),
        hInstance: crypt_ui_instance,
        pTemplateName: w!(""),
        dwFlags: CSS_ENABLETEMPLATE,
        szTitle: w!("Certificate to Sign PKCS7"),
        cCertStore: 1,
        arrayCertStore: &mut personal_store,
        // code signing
        // szPurposeOid: s!("1.3.6.1.5.5.7.3.3"),
        // on our encryption certs
        szPurposeOid: s!("1.3.6.1.4.1.311.10.3.12"),
        cCertContext: 0,
        arrayCertContext: fresh_cert,
        lCustData: windows::Win32::Foundation::LPARAM(0),
        pfnHook: UI::PFNCMHOOKPROC::None,
        pfnFilter: UI::PFNCMFILTERPROC::None,
        szHelpFileName: w!(""),
        dwHelpId: 0,
        hprov: 0,
    };

    let cert_select_certificate_w: CertSelectCertificateW = transmute(GetProcAddress(
        crypt_ui_instance,
        s!("CertSelectCertificateW"),
    ));
    cert_select_certificate_w(&cert_select_struct);
    if fresh_cert.read().is_null() {
        panic!("No certificate selected for signature.  Exiting.")
    }

    // clean-up
    if FreeLibrary(crypt_ui_instance).as_bool() {
        println!("Closed the lib")
    };
    if CertCloseStore(personal_store, 0).as_bool() {
        println!("Closed the personal_store");
    }
    Ok(())
}

pub unsafe fn get_context_cert_file(cert_bytes: &[u8]) -> Result<*mut CERT_CONTEXT> {
    let ret_val = CertCreateCertificateContext(X509_ASN_ENCODING, cert_bytes);
    if !ret_val.is_null() {
        return Ok(ret_val);
    } else {
        let buf = convert_from_pem_to_der(cert_bytes)?;

        let ret_val = CertCreateCertificateContext(X509_ASN_ENCODING, &buf);
        if !ret_val.is_null() {
            return Ok(ret_val);
        } else {
            return Err(Error::new(
                GetLastError().to_hresult(),
                HSTRING::from("Certificate context as NULL"),
            ));
        }
    }
}

pub unsafe fn do_the_signing(fresh_cert: *mut CERT_CONTEXT) {
    // Grab certificate chain
    let cert_chain_parameter = CERT_CHAIN_PARA {
        cbSize: u32::try_from(std::mem::size_of::<CERT_CHAIN_PARA>()).unwrap(),
        RequestedUsage: windows::Win32::Security::Cryptography::CERT_USAGE_MATCH::default(),
    };

    let mut fresh_chain: *mut CERT_CHAIN_CONTEXT = ::core::mem::zeroed();
    windows::Win32::Security::Cryptography::CertGetCertificateChain(
        None,
        fresh_cert,
        ::core::mem::zeroed(),
        None,
        &cert_chain_parameter,
        0,
        ::core::mem::zeroed(),
        &mut fresh_chain,
    );
    let chain_pointer = *(*(*(*fresh_chain).rgpChain)).rgpElement;
    let chain_size = (**(*fresh_chain).rgpChain).cElement;
    let chain_array = std::slice::from_raw_parts(chain_pointer, chain_size as _);
    // get second cert in data array spot 0 is the default cert, slot 1 is next up in the chain

    let intermediate_cert = chain_array[1].pCertContext.cast_mut();
    let root_cert = *(chain_array[2].pCertContext);
    let cert_raw_parts =
        std::slice::from_raw_parts(root_cert.pbCertEncoded, root_cert.cbCertEncoded as _);
    let binding = convert_from_der_to_pem(cert_raw_parts).unwrap();
    std::fs::write("current_build/dod_pke_chain.pem", binding.as_bytes()).unwrap();

    // get chain size
    let mut certs_in_signature: Vec<*mut CERT_CONTEXT> = vec![intermediate_cert, fresh_cert];

    // Sign a file with the selected cert
    // https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature

    const OID: *const u8 = "1.3.14.3.2.26\0".as_ptr();
    let crypt_sign_message_para = CRYPT_SIGN_MESSAGE_PARA {
        cbSize: u32::try_from(std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>()).unwrap(),
        dwMsgEncodingType: PKCS_7_ASN_ENCODING.0,
        pSigningCert: fresh_cert,
        HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: windows::core::PSTR::from_raw(OID.cast_mut()),
            Parameters: CRYPT_INTEGER_BLOB::default(),
        },
        pvHashAuxInfo: ::core::mem::zeroed(),
        cMsgCert: 2,
        rgpMsgCert: certs_in_signature.as_mut_ptr(),
        cMsgCrl: 0,
        rgpMsgCrl: ::core::mem::zeroed(),
        cAuthAttr: 0,
        rgAuthAttr: ::core::mem::zeroed(),
        cUnauthAttr: 0,
        rgUnauthAttr: ::core::mem::zeroed(),
        dwFlags: 0,
        dwInnerContentType: 0,
    };

    let mut sha256_string = String::new();
    for entry in WalkDir::new(".")
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() && entry.path().extension().unwrap_or_default() == "p7b" {
            let input = std::path::Path::new(entry.path().as_os_str());
            let path_string = entry.path().file_name().unwrap().to_str().unwrap();
            let val = sha256::try_digest(input).unwrap();
            let concat_string = val + " " + path_string + "\n";
            sha256_string.push_str(concat_string.as_str());
        }
    }
    sha256_string.push_str("\0");

    let s_val = PCSTR(sha256_string.as_ptr());
    let sign_me: Vec<*const u8> = vec![s_val.as_ptr()];
    let to_be_signed_sizes_array: Vec<u32> = vec![u32::try_from(s_val.as_bytes().len()).unwrap()];
    let slice = to_be_signed_sizes_array.into_boxed_slice();
    let mut data_size = 0;

    // First call sets up variables to receive the size of the signed data.
    let _sign_success = CryptSignMessage(
        &crypt_sign_message_para,
        windows::Win32::Foundation::BOOL::from(false),
        1,
        Some(sign_me.as_ptr()),
        slice.as_ptr(),
        ::core::mem::zeroed(),
        &mut data_size,
    );

    // println!("First call complete. Sign Success:{:?}", sign_success);

    let proc_heap = GetProcessHeap().unwrap();
    let blob_ptr = HeapAlloc(proc_heap, HEAP_ZERO_MEMORY, data_size as _);

    let _sign_success_2 = CryptSignMessage(
        &crypt_sign_message_para,
        windows::Win32::Foundation::BOOL::from(false),
        1,
        Some(sign_me.as_ptr()),
        slice.as_ptr(),
        Some(blob_ptr as *mut u8),
        &mut data_size,
    );

    // println!("Second call complete. Sign Success:{:?}", sign_success_2);
    let signed_data = std::slice::from_raw_parts(blob_ptr as *mut u8, data_size as _);
    std::fs::write("current_build/certificates.sha256", signed_data).unwrap();
    // println!("{:02X?}", _signed_data);

    // clean-up
    CertFreeCertificateChain(fresh_chain);
}

pub unsafe fn convert_from_pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let mut read_len = 0;
    let ok = CryptStringToBinaryA(
        pem,
        CRYPT_STRING_BASE64HEADER,
        ::core::mem::zeroed(),
        &mut read_len,
        ::core::mem::zeroed(),
        ::core::mem::zeroed(),
    );
    if ok == false {
        return Err(Error::new(
            GetLastError().to_hresult(),
            HSTRING::from("Failed converting from PEM to DER while getting the size."),
        ));
    }

    let mut buf = vec![0; read_len as usize];
    let ok = CryptStringToBinaryA(
        pem,
        CRYPT_STRING_BASE64HEADER,
        Some(buf.as_mut_ptr()),
        &mut read_len,
        ::core::mem::zeroed(),
        ::core::mem::zeroed(),
    );

    if ok == false {
        return Err(Error::new(
            GetLastError().to_hresult(),
            HSTRING::from("Failed converting from PEM to DER while tansforming."),
        ));
    } else {
        Ok(buf)
    }
}

pub unsafe fn convert_from_der_to_pem(der: &[u8]) -> Result<String> {
    let mut read_len = 0;
    let ok = CryptBinaryToStringA(
        der,
        CRYPT_STRING_BASE64HEADER,
        ::core::mem::zeroed(),
        &mut read_len,
    );
    if ok == false {
        return Err(Error::new(
            GetLastError().to_hresult(),
            HSTRING::from("Failed converting from DER to PEM while getting size."),
        ));
    }
    let mut buf = vec![0; read_len as usize];
    let mut pstr_buf = PSTR(buf.as_ptr() as _);

    let ok = CryptBinaryToStringA(der, CRYPT_STRING_BASE64HEADER, pstr_buf, &mut read_len);

    if ok == false {
        return Err(Error::new(
            GetLastError().to_hresult(),
            HSTRING::from("Failed converting from DER to PEM while transforming."),
        ));
    } else {
        Ok(pstr_buf.to_string().unwrap())
    }
}

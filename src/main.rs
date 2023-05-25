use std::path::Path;
use std::{
    collections::HashMap,
    ffi::{c_void},
    io::Write,
    mem::transmute,
};
use walkdir::WalkDir;
use windows::Win32::Security::Cryptography::{
    CertGetNameStringA, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows::{
    core::*,
    Win32::{
        Foundation::GetLastError,
        Security::Cryptography::{
            CertAddCertificateContextToStore, CertCloseStore,
            CertCreateCertificateContext, CertFreeCertificateChain, CertFreeCertificateContext,
            CertOpenStore, CertSaveStore, CryptBinaryToStringA, CryptSignMessage,
            CryptStringToBinaryA, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA,
            CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
            CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W,
            CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_FILENAME_A,
            CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
            CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB, CRYPT_SIGN_MESSAGE_PARA,
            CRYPT_STRING_BASE64HEADER, HCERTSTORE, HCRYPTPROV_LEGACY, PKCS_7_ASN_ENCODING,
            UI::{self, CERT_SELECT_STRUCT_W, CSS_ENABLETEMPLATE},
            X509_ASN_ENCODING,
        },
        System::{
            LibraryLoader::{FreeLibrary, GetProcAddress, LoadLibraryW},
            Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY},
        },
    },
};
use zip::DateTime;

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions
type CertSelectCertificateW = extern "stdcall" fn(*const CERT_SELECT_STRUCT_W);
const BUILD_DIRECTORY: &str = "current_build";

fn main() -> Result<()> {
    unsafe {
        let mut fresh_cert: *mut CERT_CONTEXT = ::core::mem::zeroed();
        let mut root_bundles: HashMap<String, HCERTSTORE> = HashMap::new();

        let mut current_dir_string: String;
        let readme_string_original: String =
            String::from_utf8_lossy(include_bytes!("readme_template.txt")).into();

        select_signing_cert(&mut fresh_cert)?;

        for entry in WalkDir::new("certificates")
            .max_depth(1)
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

                // Reading input from user, will return version number, no, or quit
                println!("Run bundle for {}? ([Y]es/[N]o/[Q]uit)", current_dir_string);
                let run_bundle = user_input_for_bundle();

                // Create and loop through main bundle
                if run_bundle.contains("_") {

                    // Create Main Bundle, stored in memory at first.
                    let main_store = CertOpenStore(
                        CERT_STORE_PROV_MEMORY,
                        CERT_QUERY_ENCODING_TYPE::default(),
                        HCRYPTPROV_LEGACY::default(),
                        CERT_OPEN_STORE_FLAGS(0),
                        ::core::mem::zeroed(),
                    )?;

                    for certificate_file in entry.path().read_dir().expect("read_dir call failure")
                    {
                        let current_file = certificate_file.unwrap().path();
                        if current_file.is_file() && current_file.extension().unwrap() == "cer" {
                            let cert_context =
                                get_context_cert_file(&std::fs::read(current_file).unwrap())?;

                            add_cert_to_bundle(cert_context, main_store, &current_dir_string);
                        }
                    }
                    // Create the mini bundles that denote each CA the certs are rooted in.
                    for certificate_file in entry.path().read_dir().expect("read_dir call failure")
                    {
                        let current_file = certificate_file.unwrap().path();
                        if current_file.is_file() && current_file.extension().unwrap() == "cer" {
                            let cert_context =
                                get_context_cert_file(&std::fs::read(current_file).unwrap())?;

                            
                            let root_name = get_chain_root_subject(cert_context, main_store);

                            let update_store: HCERTSTORE;
                            if root_bundles.contains_key(&root_name) {
                                update_store = *(root_bundles.get(&root_name).unwrap());
                            } else {
                                update_store = CertOpenStore(
                                    CERT_STORE_PROV_MEMORY,
                                    CERT_QUERY_ENCODING_TYPE::default(),
                                    HCRYPTPROV_LEGACY::default(),
                                    CERT_OPEN_STORE_FLAGS(0),
                                    ::core::mem::zeroed(),
                                )?;
                                root_bundles.insert(root_name, update_store);
                            }
                            add_cert_to_bundle_quiet(cert_context, update_store);
                        }
                    }
                    // Clean or create build directory
                    if std::fs::metadata(BUILD_DIRECTORY).is_err() {
                        std::fs::create_dir(BUILD_DIRECTORY).unwrap();
                    } else {
                        std::fs::remove_dir_all(BUILD_DIRECTORY).unwrap();
                        std::fs::create_dir(BUILD_DIRECTORY).unwrap();
                    }

                    let mut file_name = "certificates_pkcs7_v".to_owned();
                    file_name.push_str(run_bundle.trim());
                    file_name.push('_');
                    file_name.push_str(current_dir_string.to_lowercase().as_str());

                    let mut p7b_file_name = file_name.clone();
                    p7b_file_name.push_str("_der.p7b\0");

                    // Jump into build directory to make files
                    std::env::set_current_dir(BUILD_DIRECTORY).unwrap();
                    // create base bundle for current bundle

                    save_and_close_store(p7b_file_name, main_store);

                    // Create each individual bundle file
                    for x in root_bundles.clone().into_iter() {
                        let mut root_file_name = file_name.clone();
                        root_file_name.push('_');
                        // Turn spaces into _ and remove any null terminators from windows conversion
                        root_file_name.push_str(x.0.replace(" ", "_").replace("\0", "").as_str());
                        root_file_name.push_str("_der.p7b\0");

                        save_and_close_store(root_file_name, x.1);
                    }
                    root_bundles.clear();

                    // Change README to reflect the current build files
                    let mut readme_string =
                        readme_string_original.replace("IRFILENAME", file_name.as_str());
                    readme_string = readme_string.replace("SIGNINGCHAIN", "dod_pke_chain.pem");
                    std::fs::write("README.txt", readme_string.as_bytes()).unwrap();

                    std::env::set_current_dir("..").unwrap();
                    println!(
                        "\n***** Signing {} using Windows CryptSignMessage function ***** ",
                        file_name
                    );
                    do_the_signing(fresh_cert, file_name.clone());
                    zip_up_bundle(file_name);

                } else if run_bundle.contains("q") {
                    break;
                }
            }
        }

        // Clean-up
        if !CertFreeCertificateContext(Some(fresh_cert)).as_bool() {
            println!("Failed to close fresh_cert");
        }
    }
    if std::fs::metadata(BUILD_DIRECTORY).is_ok() {
        std::fs::remove_dir_all(BUILD_DIRECTORY).unwrap();
    }
    Ok(())
}

pub unsafe fn add_cert_to_bundle(cert_context: *mut CERT_CONTEXT, main_store: HCERTSTORE, current_dir_string: &String) {
    let test_add = CertAddCertificateContextToStore(
        main_store,
        cert_context,
        CERT_STORE_ADD_REPLACE_EXISTING,
        None,
    );

    if test_add.as_bool() {
        println!(
            "\nSuccessfully added cert with Subject: {} and\nIssuer: {} to the {} bundle.",
            get_cert_subject(cert_context)
                .unwrap_or("Unknown Cert Subject".to_owned()),
            get_cert_issuer(cert_context)
                .unwrap_or("Unknown Cert Issuer".to_owned()),
            &current_dir_string
        );
        //{:02X?}
    }
}

pub unsafe fn add_cert_to_bundle_quiet(cert_context: *mut CERT_CONTEXT, main_store: HCERTSTORE) {
    CertAddCertificateContextToStore(
        main_store,
        cert_context,
        CERT_STORE_ADD_REPLACE_EXISTING,
        None,
    );
}

pub unsafe fn save_and_close_store(file_name: String, store_context: HCERTSTORE) {
    let file_name_pcstr = PCSTR(file_name.as_ptr()).as_ptr();
    CertSaveStore(
        store_context,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        CERT_STORE_SAVE_AS_PKCS7,
        CERT_STORE_SAVE_TO_FILENAME_A,
        file_name_pcstr as _,
        0,
    );

    if !CertCloseStore(store_context, 0).as_bool() {
        println!("Failed to close the {} memory_store", file_name);
    }
}

unsafe fn get_chain_root_subject(cert_context: *mut CERT_CONTEXT, main_store: HCERTSTORE) -> String {
    let cert_chain_parameter = CERT_CHAIN_PARA {
        cbSize: u32::try_from(std::mem::size_of::<CERT_CHAIN_PARA>()).unwrap(),
        RequestedUsage: windows::Win32::Security::Cryptography::CERT_USAGE_MATCH::default(),
    };

    let mut fresh_chain: *mut CERT_CHAIN_CONTEXT = ::core::mem::zeroed();
    windows::Win32::Security::Cryptography::CertGetCertificateChain(
        None,
        cert_context,
        ::core::mem::zeroed(),
        main_store,
        &cert_chain_parameter,
        0,
        ::core::mem::zeroed(),
        &mut fresh_chain,
    );
    let chain_pointer = *(*(*(*fresh_chain).rgpChain)).rgpElement;
    let chain_size = (**(*fresh_chain).rgpChain).cElement;
    let chain_array =
        std::slice::from_raw_parts(chain_pointer, chain_size as _);
    let root_cert = chain_array.last().unwrap().pCertContext.cast_mut();
    return get_cert_subject(root_cert).unwrap_or("unknown_root".to_owned());
}

pub unsafe fn get_cert_subject(cert: *mut CERT_CONTEXT) -> Option<String> {
    let array_size = CertGetNameStringA(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        ::core::mem::zeroed(),
        ::core::mem::zeroed(),
        None,
    );
    let mut buf: Vec<u8> = vec![0; array_size as usize];

    CertGetNameStringA(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        ::core::mem::zeroed(),
        ::core::mem::zeroed(),
        Some(&mut buf),
    );

    let subject_string = String::from_utf8_lossy(&buf).to_string();
    Some(subject_string.trim_end().to_string())
}

pub unsafe fn get_cert_issuer(cert: *mut CERT_CONTEXT) -> Option<String> {
    let array_size = CertGetNameStringA(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        ::core::mem::zeroed(),
        None,
    );
    let mut buf: Vec<u8> = vec![0; array_size as usize];

    CertGetNameStringA(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        ::core::mem::zeroed(),
        Some(&mut buf),
    );

    let issuer_string = String::from_utf8_lossy(&buf).to_string();
    Some(issuer_string.trim_end().to_string())
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
        if std::fs::metadata(BUILD_DIRECTORY).is_ok() {
            std::fs::remove_dir_all(BUILD_DIRECTORY).unwrap();
        }
        panic!("No certificate selected for signature.  Exiting.")
    }

    // clean-up
    if !FreeLibrary(crypt_ui_instance).as_bool() {
        println!("Failed to close the cryptography library.")
    }
    if !CertCloseStore(personal_store, 0).as_bool() {
        println!("Failed to close the personal_store.");
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

pub unsafe fn do_the_signing(fresh_cert: *mut CERT_CONTEXT, file_name: String) {
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
    let chain_size = chain_array.len();
    let intermediate_cert: *mut CERT_CONTEXT;//chain_array[1].pCertContext.cast_mut();
    let mut certs_in_signature: Vec<*mut CERT_CONTEXT>;
    if chain_size > 2 {
        intermediate_cert = chain_array[1].pCertContext.cast_mut();
        certs_in_signature = vec![intermediate_cert, fresh_cert];
        let root_cert = *(chain_array.last().unwrap().pCertContext);
        let root_cert_raw_parts =
            std::slice::from_raw_parts(root_cert.pbCertEncoded, root_cert.cbCertEncoded as _);
        let root_cert_pem_string = convert_from_der_to_pem(root_cert_raw_parts).unwrap();
        std::fs::write(
            "current_build/dod_pke_chain.pem",
            root_cert_pem_string.as_bytes(),
        )
        .unwrap();
    } else if chain_size > 1 {
        intermediate_cert = chain_array[1].pCertContext.cast_mut();
        certs_in_signature = vec![intermediate_cert, fresh_cert];
        let intermed_cert_raw_parts = std::slice::from_raw_parts(
            (*intermediate_cert).pbCertEncoded,
            (*intermediate_cert).cbCertEncoded as _,
        );
        let intermed_cert_pem_string = convert_from_der_to_pem(intermed_cert_raw_parts).unwrap();
        std::fs::write(
            "current_build/intermed_pke_chain.pem",
            intermed_cert_pem_string.as_bytes(),
        )
        .unwrap();
    } else {
        certs_in_signature = vec![fresh_cert];
    }

    // get chain size
    //let mut certs_in_signature: Vec<*mut CERT_CONTEXT> = vec![intermediate_cert, fresh_cert];

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
    for entry in WalkDir::new(BUILD_DIRECTORY)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
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
    let sign_success = CryptSignMessage(
        &crypt_sign_message_para,
        windows::Win32::Foundation::BOOL::from(false),
        1,
        Some(sign_me.as_ptr()),
        slice.as_ptr(),
        ::core::mem::zeroed(),
        &mut data_size,
    );

    if !sign_success.as_bool() {
        if std::fs::metadata(BUILD_DIRECTORY).is_ok() {
            std::fs::remove_dir_all(BUILD_DIRECTORY).unwrap();
        }
        panic!("Error on first sign.  Operation may have been cancelled or card may not be inserted.")
    }

    let proc_heap = GetProcessHeap().unwrap();
    let blob_ptr = HeapAlloc(proc_heap, HEAP_ZERO_MEMORY, data_size as _);

    let sign_success2 = CryptSignMessage(
        &crypt_sign_message_para,
        windows::Win32::Foundation::BOOL::from(false),
        1,
        Some(sign_me.as_ptr()),
        slice.as_ptr(),
        Some(blob_ptr as *mut u8),
        &mut data_size,
    );

    if !sign_success2.as_bool() {
        if std::fs::metadata(BUILD_DIRECTORY).is_ok() {
            std::fs::remove_dir_all(BUILD_DIRECTORY).unwrap();
        }
        panic!("Error on second sign.  Operation may have been cancelled or card may not be inserted.")
    }

    // println!("Second call complete. Sign Success:{:?}", sign_success_2);
    let signed_data = std::slice::from_raw_parts(blob_ptr as *mut u8, data_size as _);
    let mut sha_256_file_name = String::from(BUILD_DIRECTORY);
    sha_256_file_name.push('/');
    sha_256_file_name.push_str(file_name.as_str());
    sha_256_file_name.push_str(".sha256");
    std::fs::write(sha_256_file_name, signed_data).unwrap();
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
    let buf = vec![0; read_len as usize];
    let pstr_buf = PSTR(buf.as_ptr() as _);

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

pub unsafe fn zip_up_bundle(file_name: String) {
    let mut zip_file_name = file_name.clone();
    zip_file_name.push_str(".zip");
    let zipper = std::fs::File::create(zip_file_name).unwrap();
    let mut zip = zip::ZipWriter::new(zipper);
    let date_time = DateTime::try_from(time::OffsetDateTime::now_local().unwrap()).unwrap();
    let zip_options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(date_time);

    for entry in WalkDir::new(BUILD_DIRECTORY)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            let current_file = entry.path().file_name().unwrap().to_str().unwrap();
            zip.start_file(file_name.clone() + "/" + current_file, zip_options)
                .unwrap();
            zip.write_all(&std::fs::read(entry.path().to_str().unwrap()).unwrap())
                .unwrap();
        }
    }

    zip.finish().unwrap();
}

pub unsafe fn user_input_for_bundle() -> String {
    let mut input = String::new();
    loop {
        input.clear();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input.");
        input = input.to_lowercase();
        if input.contains("yes") || input.contains("y") {
            input.clear();
            println!("What bundle number would for this bundle?  i.e. 5_2 or 1_2_345");
            loop {
                std::io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to read input.");
                if input.split("_").count() > 1
                    && input
                        .split("_")
                        .all(|num| num.trim().parse::<u32>().is_ok())
                {
                    return input;
                }
                println!(
                    "Error with input, must be at least two numbers seperated by an underscore."
                );
                input.clear();
            }
        } else if input.contains("no")
            || input.contains("n")
            || input.contains("quit")
            || input.contains("q")
        {
            return input;
        }
        println!("Error with input, must be one of these three options ([Y]es/[N]o/[Q]uit)")
    }
}

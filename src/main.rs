#![allow(unused_imports)]
use std::{ffi::{c_void}, mem::transmute};
use windows::{
    core::*, Win32::{
        Security::Cryptography::{
        UI::{CERT_SELECT_STRUCT_W, CSS_ENABLETEMPLATE, self}, 
        CERT_STORE_PROV_SYSTEM_W, CERT_QUERY_ENCODING_TYPE, HCRYPTPROV_LEGACY, CERT_SYSTEM_STORE_CURRENT_USER_ID, 
        CertOpenStore, CERT_SYSTEM_STORE_LOCATION_SHIFT, CERT_OPEN_STORE_FLAGS, CERT_CONTEXT, 
        CRYPT_SIGN_MESSAGE_PARA, PKCS_7_ASN_ENCODING, CryptSignMessage, CertFreeCertificateContext, 
        CertCloseStore, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_INTEGER_BLOB, CERT_CHAIN_PARA, CERT_CHAIN_CONTEXT
        }, System::{
            LibraryLoader::{GetProcAddress, LoadLibraryW, FreeLibrary}, 
            Memory::{HeapAlloc, GetProcessHeap, HEAP_ZERO_MEMORY}
        },  Storage::FileSystem::{
            CreateFileW, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 
        }
    },
};

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions
type CertSelectCertificateW = extern "stdcall" fn(*const CERT_SELECT_STRUCT_W);

fn main() -> Result<()> {

unsafe {
        let store_name = w!("My").as_ptr() as *const c_void;
        let mut fresh_cert: *mut CERT_CONTEXT = ::core::mem::zeroed();

        let mut personal_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT),
            Some(store_name))?;

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
            arrayCertContext: &mut fresh_cert,
            lCustData: windows::Win32::Foundation::LPARAM(0),
            pfnHook: UI::PFNCMHOOKPROC::None,
            pfnFilter: UI::PFNCMFILTERPROC::None,
            szHelpFileName: w!(""),
            dwHelpId: 0,
            hprov: 0,
        };

        let cert_select_certificate_w: CertSelectCertificateW = transmute(
            GetProcAddress(crypt_ui_instance, s!("CertSelectCertificateW")));
        cert_select_certificate_w(&cert_select_struct);
        if fresh_cert.is_null() { std::process::exit(1); }

        // Sign a file with the selected cert
        // https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature
        /*
        const OID: *const u8 = "1.3.14.3.2.26\0".as_ptr();
        let crypt_sign_message_para = CRYPT_SIGN_MESSAGE_PARA {
            cbSize: u32::try_from(std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>()).unwrap(),
            dwMsgEncodingType: PKCS_7_ASN_ENCODING.0,
            pSigningCert: fresh_cert,
            HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER { 
                            pszObjId: windows::core::PSTR::from_raw(OID.cast_mut()), 
                            Parameters: CRYPT_INTEGER_BLOB::default() },
            pvHashAuxInfo: ::core::mem::zeroed(),
            cMsgCert: 1,
            rgpMsgCert: &mut fresh_cert,
            cMsgCrl: 0,
            rgpMsgCrl: ::core::mem::zeroed(),
            cAuthAttr: 0,
            rgAuthAttr: ::core::mem::zeroed(),
            cUnauthAttr: 0,
            rgUnauthAttr: ::core::mem::zeroed(),
            dwFlags: 0,
            dwInnerContentType: 0 };

        let secret_message: PCSTR = s!("Secret Message");
        let sign_me:Vec<*const u8> = vec!(secret_message.as_ptr());
        let to_be_signed_sizes_array:Vec<u32> = vec!(u32::try_from(secret_message.as_bytes().len()).unwrap());
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
            &mut data_size);

        println!("First call complete. Sign Success:{:?}", sign_success);

        let proc_heap = GetProcessHeap()?;
        let blob_ptr = HeapAlloc(proc_heap, HEAP_ZERO_MEMORY, data_size as _);

        let sign_success_2 = CryptSignMessage(
            &crypt_sign_message_para,
            windows::Win32::Foundation::BOOL::from(false),
            1,
            Some(sign_me.as_ptr()),
            slice.as_ptr(),
            Some(blob_ptr as *mut u8),
            &mut data_size);
        
        let qs = std::slice::from_raw_parts(blob_ptr as *mut u8, data_size as _);
        println!("UTF8?: {:02X?}", qs);

        let _file_interaction = CreateFileW(
            w!("c:\\users\\hrich\\desktop\\root_pkcs7_store.p7b"),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None)?;

        let file_saved = WriteFile(
            file_interaction,
            Some(un_wrap.),
            &mut data_size,
            0); */
        let cert_chain_parameter = CERT_CHAIN_PARA {
            cbSize: u32::try_from(std::mem::size_of::<CERT_CHAIN_PARA>()).unwrap(),
            RequestedUsage: windows::Win32::Security::Cryptography::CERT_USAGE_MATCH::default(),
        };

        let mut fresh_chain: *mut CERT_CHAIN_CONTEXT = ::core::mem::zeroed();
        let _cert_chain = windows::Win32::Security::Cryptography::CertGetCertificateChain (
            None,
            fresh_cert,
            ::core::mem::zeroed(),
            None,
            &cert_chain_parameter,
            0,
            ::core::mem::zeroed(),
            &mut fresh_chain,
        );
        let test = (*(*(*(*(*(*(*fresh_chain).rgpChain)).rgpElement)).pCertContext).pCertInfo).Subject;
        let test1 = **(*(*(*fresh_chain).rgpChain)).rgpElement;
        dbg!(test);
        dbg!(test1);

        if FreeLibrary(crypt_ui_instance).as_bool() { println!("Closed lib") };
        if !CertFreeCertificateContext(Some(fresh_cert)).as_bool() {
            println!("Couldn't close the cert context.");
        } else {
            println!("Closed the fresh_cert");
        }
        if !CertCloseStore(personal_store, 0).as_bool() {
            println!("Couldn't close the store.");
        } else {
            println!("Closed the personal_store");
        }
 

    } 
    Ok(())
}


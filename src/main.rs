#![allow(unused_imports)]
use std::{ffi::c_void, mem::transmute, ptr, ops::BitOr};
use windows::{
    core::*, Win32::{
        Security::Cryptography::{
        UI::{CryptUIWizDigitalSign, CERT_SELECT_STRUCT_W, CSS_ENABLETEMPLATE, self}, 
        CERT_STORE_PROV_SYSTEM_W, CERT_QUERY_ENCODING_TYPE, HCRYPTPROV_LEGACY, CERT_SYSTEM_STORE_CURRENT_USER_ID, 
        CertOpenStore, CERT_SYSTEM_STORE_LOCATION_SHIFT, CERT_STORE_PROV_MEMORY, CERT_OPEN_STORE_FLAGS, CERT_CONTEXT, 
        CRYPT_SIGN_MESSAGE_PARA, X509_ASN_ENCODING, PKCS_7_ASN_ENCODING, CryptSignMessage, CertFreeCertificateContext, 
        CertCloseStore, CRYPT_ALGORITHM_IDENTIFIER, CryptAcquireCertificatePrivateKey, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_CACHE_FLAG, CERT_KEY_SPEC, CRYPT_INTEGER_BLOB
        }, System::{
            Threading::{CreateEventW, WaitForSingleObject, SetEvent}, LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW}
        }, Foundation::{
            CloseHandle, WPARAM, LPARAM, HWND, BOOL
        }, 
        UI::WindowsAndMessaging::MessageBoxW
    },
};

// https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions

type CertSelectCertificateW = extern "stdcall" fn(*const CERT_SELECT_STRUCT_W);

static OID: &str = "1.2.840.113549.1.1.5\0";

fn main() -> Result<()> {
    unsafe {
        // Copied from example, don't know what it does
        /* 
        let event = CreateEventW(None, true, false, None).unwrap();
        SetEvent(event);
        
        WaitForSingleObject(event, 0);
        CloseHandle(event);

        MessageBoxW(0, w!("Wide"), w!("Caption"), MB_OK); */
       
        
        let store_name = w!("My").as_ptr() as *const c_void;
        let mut personal_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT),
            Some(store_name))?;

        let memory_store = CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS(0),
            ::core::mem::zeroed())?;
        
        //println!("Error after Handle: {:?}", GetLastError());

        let mut fresh_cert: *mut CERT_CONTEXT = ::core::mem::zeroed();

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
            //szPurposeOid: s!("1.3.6.1.4.1.311.10.3.12"),
            szPurposeOid: s!(""),
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

        // Displays selected cert
        /* UI::CryptUIDlgViewContext(
            CERT_STORE_CERTIFICATE_CONTEXT,
            fresh_cert as *mut c_void,
            None,
            w!("Selected Certificate"),
            0,
            ::core::mem::zeroed(),
        ); */

        // Acquire Private Key for Certificate
/*         let h_crypt_prov = ::core::mem::zeroed();
        let mut pdw_key_spec:CERT_KEY_SPEC = windows::Win32::Security::Cryptography::CERT_KEY_SPEC(5000u32);
        let mut pf_caller_free: BOOL = BOOL::default();
        let _key_acquired = CryptAcquireCertificatePrivateKey (
            fresh_cert,
            CRYPT_ACQUIRE_CACHE_FLAG,
            ::core::mem::zeroed(),
            h_crypt_prov,
            Some(&mut pdw_key_spec),
            Some(&mut pf_caller_free),
        ); */

        // Sign a file with the selected cert
        // https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature
        //let oid = "1.2.840.113549.1.1.5\0".to_owned().as_mut_ptr();
        
        //let pointer_to_oid = std::ptr::addr_of_mut!(OID.as_mut_ptr());
        let crypt_sign_message_para = CRYPT_SIGN_MESSAGE_PARA {
            cbSize: u32::try_from(std::mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>()).unwrap(),
            dwMsgEncodingType: X509_ASN_ENCODING.0,
            pSigningCert: fresh_cert,
            HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER { 
                            pszObjId: windows::core::PSTR::from_raw(OID.to_owned().as_mut_ptr()), 
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
            dwInnerContentType: 0};

        let secret_message: PCSTR = s!("Secret Message");
        let sign_me:Vec<*const u8> = vec!(secret_message.as_ptr());
        let to_be_signed_sizes_array:Vec<u32> = vec!(u32::try_from(secret_message.as_bytes().len()).unwrap());
        let mut data_size = 0;

        // First call sets up variables to receive the size of the signed data.
        let sign_success = CryptSignMessage(
            &crypt_sign_message_para,
            windows::Win32::Foundation::BOOL::from(false),
            1,
            Some(sign_me.as_ptr()),
            to_be_signed_sizes_array.as_ptr(),
            ::core::mem::zeroed(),
            &mut data_size);


        println!("First call complete.");

        let return_buffer: u32 = 50000;
        let _return_pointer: *mut u8 = return_buffer as *mut u8;
        /* let pb_signed_message_blob: *mut u8 = ::core::mem::zeroed();
        let _sign_success_2 = CryptSignMessage(
            &crypt_sign_message_para,
            windows::Win32::Foundation::BOOL::from(false),
            1,
            Some(SIGN_ME.as_ptr()),
            std::mem::size_of_val(&SIGN_ME) as *const u32,
            Some(pb_signed_message_blob),
            ::core::mem::zeroed(),
        ); */
        println!("Created _sign_success : {:?}", sign_success);
        /*
        let mssign_instance = LoadLibraryW(w!("Mssign32.dll"))?;
        let signer_time_stamp_ex2: CertSelectCertificateW = transmute(
            GetProcAddress(mssign_instance, s!("SignerTimeStampEx2")));
        let singer_sign_ex2: CertSelectCertificateW = transmute(
            GetProcAddress(mssign_instance, s!("SignerSignEx2")));

        let h_result = signer_time_stamp_ex2();
        let h_result_other = singer_sign_ex2();

         */
        if !CertFreeCertificateContext(Some(fresh_cert)).as_bool() {
            println!("Couldn't close the cert context.");
        }
        if !CertCloseStore(personal_store, 0).as_bool() {
            println!("Couldn't close the store.");
        }
        if !CertCloseStore(memory_store, 0).as_bool() {
            println!("Couldn't close the store.");
        }

    }

    Ok(())
}
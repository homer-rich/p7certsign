#![allow(unused_imports)]
use std::{ffi::c_void, mem::transmute, ptr};
use windows::{
    core::*, Win32::{Security::Cryptography::{*, UI::{CryptUIWizDigitalSign, CERT_SELECT_STRUCT_W, CSS_ENABLETEMPLATE}}, System::{Threading::{CreateEventW, WaitForSingleObject, SetEvent}, LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW}}, Foundation::{CloseHandle, WPARAM, LPARAM, HWND}, UI::WindowsAndMessaging::MessageBoxW},
};

type CertSelectCertificateW = extern "stdcall" fn(*const CERT_SELECT_STRUCT_W);

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
            hwndParent: None.into(),
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

        // Displays selected cert
        UI::CryptUIDlgViewContext(
            CERT_STORE_CERTIFICATE_CONTEXT,
            fresh_cert as *mut c_void,
            None,
            w!("Selected Certificate"),
            0,
            ::core::mem::zeroed(),
        );

        // Sign a file with the selected cert
        // https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-signing-a-message-and-verifying-a-message-signature
        let crypt_sign_message_para = CRYPT_SIGN_MESSAGE_PARA {
            cbSize: 0,
            dwMsgEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            pSigningCert: fresh_cert,
            HashAlgorithm: 0,
            pvHashAuxInfo: 0,
            cMsgCert: 0,
            rgpMsgCert: 0,
            cMsgCrl: 0,
            rgpMsgCrl: 0,
            cAuthAttr: 0,
            rgAuthAttr: 0,
            cUnauthAttr: 0,
            rgUnauthAttr: 0,
            dwFlags: 0,
            dwInnerContentType: 0,
        };

        let sign_success = CryptSignMessage();
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
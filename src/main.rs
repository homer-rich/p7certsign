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

/* 
        let cert_subj = w!("DoD JITC Root CA 3").as_ptr() as *mut c_void;
        let find_cert = CertFindCertificateInStore(
            personal_store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            Some(cert_subj),
            ::core::mem::zeroed()); */

        let mut fresh_cert: *mut CERT_CONTEXT = ::core::mem::zeroed();

        //println!("We HSTRING??:  {:?}", strang);
        //let file_interaction = CreateFileW(w!("c:\\users\\hrich\\desktop\\root_pkcs7_store.p7b"), FILE_GENERIC_WRITE, FILE_SHARE_WRITE, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None).unwrap();
        //println!("How's the HANDLE?: {:?}", file_interaction);
        //println!("Error after Handle: {:?}", GetLastError());
        

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
            // szPurposeOid: s!(""),
            cCertContext: 0,
            arrayCertContext: &mut fresh_cert,
            lCustData: windows::Win32::Foundation::LPARAM(0),
            pfnHook: UI::PFNCMHOOKPROC::None,
            pfnFilter: UI::PFNCMFILTERPROC::None,
            szHelpFileName: w!(""),
            dwHelpId: 0,
            hprov: 0,
        };

        let call_cert_select: CertSelectCertificateW = transmute(GetProcAddress(crypt_ui_instance, s!("CertSelectCertificateW")));
        call_cert_select(&cert_select_struct);
        if fresh_cert.is_null() { std::process::exit(1); }

        /* Displays celected cert */
        UI::CryptUIDlgViewContext(
            CERT_STORE_CERTIFICATE_CONTEXT,
            fresh_cert as *mut c_void,
            None,
            w!("Selected Certificate"),
            0,
            ::core::mem::zeroed(),
        );

        //fresh_cert.
        //let mut empty_crypt_attribute = CRYPT_ATTRIBUTES;
        //static constant_cert: *const CERT_CONTEXT = constant_cert.clone_from(fresh_cert);

        let mut extended_sign_info: UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO = UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO {
            dwSize: std::mem::size_of::<UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO>() as u32,
            dwAttrFlags: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INDIVIDUAL,
            pwszDescription: w!("My Cert"),
            pwszMoreInfoLocation: w!(""),
            pszHashAlg: s!(""),
            pwszSigningCertDisplayString: w!("Test"),
            hAdditionalCertStore: ::core::mem::zeroed(),
            psAuthenticated: ::core::mem::zeroed(),
            psUnauthenticated: ::core::mem::zeroed(),
        };

        let sign_info: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO = UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO {
            dwSize: std::mem::size_of::<UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO>() as u32,
            dwSubjectChoice: windows::Win32::Security::Cryptography::UI::CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT(0),
            Anonymous1: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO_0{ pwszFileName: w!("") },
            dwSigningCertChoice: UI::CRYPTUI_WIZ_DIGITAL_SIGN_CERT,
            Anonymous2: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO_1 { pSigningCertContext: fresh_cert },
            pwszTimestampURL: w!(""),
            dwAdditionalCertChoice: UI::CRYPTUI_WIZ_DIGITAL_ADDITIONAL_CERT_CHOICE(0),
            pSignExtInfo: &mut extended_sign_info as *mut UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO,
        };

        let show_me_signature = UI::CryptUIWizDigitalSign(
            0,
            None,
            w!("Title"),
            &sign_info as *const UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO, 
            ::core::mem::zeroed(), 
        );
        if show_me_signature.as_bool() { println!("True") } else { println!("False") }
        
        if !CertFreeCertificateContext(Some(fresh_cert)).as_bool() {
            println!("Couldn't close the cert context.");
        }
        if !CertCloseStore(personal_store, 0).as_bool() {
            println!("Couldn't close the store.");
        }
        if !CertCloseStore(memory_store, 0).as_bool() {
            println!("Couldn't close the store.");
        }

        //println!("Certificate info: {:?}", cert_subby);
        //let success_select = CertSelectCertificateW(cert_select_struct);
        // let hinstance = winapi::um::libloaderapi::GetModuleHandleW(std::ptr::null_mut());
        // std::mem::size_of::<CERT_SELECT_STRUCT_W>() as u32
        /*
        let strang = w!("Signer_Box").abi().as_ptr() as *mut c_void;
        let digital_sign = CryptUIWizDigitalSign(
            0,
            event,
            strang,
            
        );
        let strang = w!("c:\\users\\hrich\\desktop\\memory_store.p7b").as_ptr() as *mut c_void;
        let save_to_store = CertAddCertificateContextToStore(
            memory_store,
            fresh_cert,
            CERT_STORE_ADD_REPLACE_EXISTING,
            None);
        let success = CertSaveStore(
            memory_store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_FILENAME_W,
            strang,
            0);
        */
        //MessageBoxW(None, w!("Wide"), w!("Caption"), windows::Win32::UI::WindowsAndMessaging::MB_OK);
        //println!("We happy?:  {:?}", success);
        //println!("We saved to memory?:  {:?}", save_to_store);


    }

    Ok(())
}
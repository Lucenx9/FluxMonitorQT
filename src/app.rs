use cpp::cpp;
use std::ffi::c_void;

cpp!{{
    #include <QtWidgets/QApplication>
    #include <iostream>
}}

pub fn test_cpp_ffi() {
    unsafe {
        cpp!([] {
            std::cerr << "DEBUG: C++ FFI works" << std::endl;
        })
    }
}

pub fn init_qapplication() -> *mut c_void {
    unsafe {
        cpp!([] -> *mut c_void as "QApplication*" {
            try {
                static int argc = 1;
                static char app_name[] = "netmon";
                static char *argv[] = { app_name, nullptr };
                QApplication *app = new QApplication(argc, argv);
                
                // Fix invalid font description warnings by setting a simpler default font
                QFont font = app->font();
                font.setFamily("Sans Serif");
                app->setFont(font);
                
                return app;
            } catch (const std::exception& e) {
                std::cerr << "Qt Initialization Error: " << e.what() << std::endl;
                std::cerr << "This often happens in headless environments without a valid DISPLAY." << std::endl;
                return nullptr;
            } catch (...) {
                std::cerr << "Unknown Error during Qt Initialization." << std::endl;
                return nullptr;
            }
        })
    }
}

pub fn exec_qapplication(app: *mut c_void) {
    unsafe {
        cpp!([app as "QApplication*"] {
            // exec() blocks until quit
            app->exec();
        });
    }
}

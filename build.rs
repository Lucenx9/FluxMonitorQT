fn main() {
    let pkgs = vec!["Qt5Widgets", "Qt5Gui", "Qt5Core"];
    let mut config = cpp_build::Config::new();
    
    let mut found_all = true;
    for pkg in pkgs {
        match pkg_config::probe_library(pkg) {
            Ok(lib) => {
                println!("cargo:warning=Found library: {}", pkg);
                for include in lib.include_paths {
                    config.include(include);
                }
            }
            Err(e) => {
                println!("cargo:warning=Could not find library {}: {}", pkg, e);
                found_all = false;
            }
        }
    }

    if !found_all {
        println!("cargo:warning=Qt5 libraries missing. Build may fail.");
        // We might want to panic here, but let's try to proceed to see errors if it's just a pkg-config quirk
    }

    config.build("src/lib.rs");
}

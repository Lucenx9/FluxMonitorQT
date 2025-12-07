use flux_monitor_qt::{app, monitor, ui};
use crossbeam_channel::unbounded;
use std::thread;
use std::time::Duration;

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    eprintln!("DEBUG: Started main");

    // Check for display environment to prevent headless segfaults
    if std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err() {
        eprintln!("Error: No display environment found (DISPLAY or WAYLAND_DISPLAY not set).");
        eprintln!("This is a GUI application and requires a graphical desktop environment to run.");
        std::process::exit(1);
    }

    // Check permissions
    // Check permissions
    let has_permissions = match monitor::NetworkMonitor::check_permissions() {
        Ok(_) => {
            eprintln!("INFO: Permissions OK - can read /proc");
            true
        }
        Err(e) => {
            eprintln!("WARNING: {}", e);
            eprintln!("WARNING: Some connections may not be visible.");
            eprintln!("HINT: Run with sudo for full visibility: sudo {}",
                std::env::args().next().unwrap_or_else(|| "./network-monitor".to_string()));
            false
        }
    };

    eprintln!("DEBUG: Testing minimal C++ FFI");
    app::test_cpp_ffi();

    eprintln!("DEBUG: Initializing QApplication");
    let _app = app::init_qapplication();

    if _app.is_null() {
        eprintln!("DEBUG: QApplication is null");
        std::process::exit(1);
    }
    eprintln!("DEBUG: QApplication initialized");
    eprintln!("DEBUG: QApplication struct created");

    // Parse command line args for debug mode
    let debug = std::env::args().any(|arg| arg == "--debug" || arg == "-d");
    if debug {
        eprintln!("DEBUG MODE ENABLED");
    }

    let (tx, rx) = unbounded();
    let (filter_tx, filter_rx) = unbounded();

    // Monitor Thread
    thread::spawn(move || {
        let mut monitor = monitor::NetworkMonitor::new_with_debug(debug);
        let mut current_filter = monitor::ConnectionFilter::new();
        
        loop {
            // Check for filter updates
             while let Ok(new_filter) = filter_rx.try_recv() {
                current_filter = new_filter;
                eprintln!("DEBUG: Updated filter: Localhost hidden={}", current_filter.filter_localhost);
            }
            
            let (connections, stats) = monitor.update_with_filter(&current_filter);
            let _ = tx.send((connections, stats));
            thread::sleep(Duration::from_millis(500));
        }
    });

    eprintln!("DEBUG: Creating window");
    let mut window = ui::NetMonWindow::new(rx, filter_tx, has_permissions);
    eprintln!("DEBUG: Showing window");
    window.show();
    eprintln!("DEBUG: Window shown");

    ::log::info!("About to exec QApplication...");
    app::exec_qapplication(_app);
    ::log::info!("QApplication exited.");
}

use qmetaobject::*;
use crate::monitor::{ConnectionInfo, NetworkStats, ConnectionFilter};
use cpp::cpp;
use std::ffi::CStr;
use std::os::raw::c_char;

cpp! {{
    #include <QtWidgets/QApplication>
    #include <QtWidgets/QMainWindow>
    #include <QtWidgets/QTableView>
    #include <QtWidgets/QVBoxLayout>
    #include <QtWidgets/QHBoxLayout>
    #include <QtWidgets/QLineEdit>
    #include <QtWidgets/QLabel>
    #include <QtWidgets/QCheckBox>
    #include <QtWidgets/QStatusBar>
    #include <QtWidgets/QHeaderView>
    #include <QtCore/QAbstractTableModel>
    #include <QtCore/QSortFilterProxyModel>
    #include <QtCore/QTimer>
    #include <QtWidgets/QSystemTrayIcon>
    #include <QtWidgets/QMenu>
    #include <QtWidgets/QStyle>
    #include <iostream>
    #include <utility>

    extern "C" int rust_model_row_count(void*);
    extern "C" int rust_model_column_count(void*);

    extern "C" void rust_model_data(void*, int, int, int, QVariant*);
    extern "C" void rust_model_header_data(void*, int, QVariant*);

    extern "C" void rust_poll_updates(void*);
    extern "C" void rust_update_filter(void*, const char*, const char*, const char*, bool);

    class RustTableModel : public QAbstractTableModel {
    public:
        void* rust_object;

        RustTableModel(void* obj, QObject* parent = nullptr) : QAbstractTableModel(parent), rust_object(obj) {}

        int rowCount(const QModelIndex &parent = QModelIndex()) const override {
            if (parent.isValid()) return 0;
            return rust_model_row_count(rust_object);
        }

        int columnCount(const QModelIndex &parent = QModelIndex()) const override {
            if (parent.isValid()) return 0;
            return rust_model_column_count(rust_object);
        }

        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override {
            if (!index.isValid()) return QVariant();
            QVariant result;
            rust_model_data(rust_object, index.row(), index.column(), role, &result);
            return result;
        }

        QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
            if (role != Qt::DisplayRole) return QVariant();
            QVariant result;
            if (orientation == Qt::Horizontal) {
                rust_model_header_data(rust_object, section, &result);
            }
            return result;
        }

        void refresh() {
            beginResetModel();
            endResetModel();
        }
    };

    class NetMonSortProxy : public QSortFilterProxyModel {
    public:
        NetMonSortProxy(QObject* parent = nullptr) : QSortFilterProxyModel(parent) {}

    protected:
        bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override {
            // Speed columns: 8 (Upload), 9 (Download)
            if (source_left.column() == 8 || source_left.column() == 9) {
                QVariant leftData = sourceModel()->data(source_left, Qt::UserRole);
                QVariant rightData = sourceModel()->data(source_right, Qt::UserRole);
                return leftData.toULongLong() < rightData.toULongLong();
            }
            return QSortFilterProxyModel::lessThan(source_left, source_right);
        }
    };

    // Helper function to update statusbar
    void update_statusbar_cpp(void* statusbar_ptr, const QString& msg) {
        QStatusBar* statusBar = (QStatusBar*)statusbar_ptr;
        if (statusBar) {
            statusBar->showMessage(msg);
        }
    }
}}

pub struct NetMonModel {
    pub data: Vec<ConnectionInfo>,
}

fn format_speed(bytes_per_sec: u64) -> String {
    if bytes_per_sec < 1024 {
        format!("{} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024 * 1024 {
        format!("{:.2} KB/s", bytes_per_sec as f64 / 1024.0)
    } else if bytes_per_sec < 1024 * 1024 * 1024 {
        format!("{:.2} MB/s", bytes_per_sec as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB/s", bytes_per_sec as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// Simpler approach: Pass the statusbar pointer and QString as a reference
// The trick is to pass QString by reference/pointer to avoid cpp! macro issues
fn update_statusbar_impl(statusbar_ptr: usize, msg: String) {
    if statusbar_ptr == 0 {
        return;
    }

    // Convert to QString
    let qstr = QString::from(msg);

    // Get raw pointer to QString
    let qstr_ptr = &qstr as *const QString;

    // SAFETY: statusbar_ptr is a valid pointer to a QStatusBar created in create_window_impl.
    // qstr_ptr points to a valid QString on the stack that outlives this unsafe block.
    // The C++ code only reads from qstr_ptr and doesn't retain any references after the call.
    unsafe {
        cpp!([statusbar_ptr as "void*", qstr_ptr as "const QString*"] {
            QStatusBar* bar = (QStatusBar*)statusbar_ptr;
            if (bar && qstr_ptr) {
                bar->showMessage(*qstr_ptr);
            }
        });
    }
}

fn create_window_impl(model_raw: usize, self_ptr: usize, has_permissions: bool) -> (usize, usize) {
    // SAFETY: model_raw is a valid pointer to NetMonModel created from &*self.model_data.
    // self_ptr is a valid pointer to NetMonWindow created from self.
    // Both pointers remain valid for the lifetime of the NetMonWindow instance.
    // The C++ code stores these pointers and uses them for callbacks, which is safe
    // because the NetMonWindow owns the model and outlives the Qt widgets.
    unsafe {
        cpp!([model_raw as "void*", self_ptr as "void*", has_permissions as "bool"] -> (usize, usize) as "std::pair<size_t, size_t>" {
             try {
                 std::cerr << "DEBUG: C++: Starting Window Creation" << std::endl;
                 QMainWindow *window = new QMainWindow();
                 std::cerr << "DEBUG: C++: QMainWindow created" << std::endl;
                 window->resize(900, 600);
                 window->setWindowTitle("FluxMonitorQT");
                 
                 // System Tray
                 if (QSystemTrayIcon::isSystemTrayAvailable()) {
                     QSystemTrayIcon *trayIcon = new QSystemTrayIcon(window);
                     trayIcon->setIcon(window->style()->standardIcon(QStyle::SP_ComputerIcon));
                     
                     QMenu *trayMenu = new QMenu(window);
                     QAction *showAction = trayMenu->addAction("Show");
                     QAction *quitAction = trayMenu->addAction("Quit");
                     
                     QObject::connect(showAction, &QAction::triggered, window, &QMainWindow::showNormal);
                     QObject::connect(quitAction, &QAction::triggered, &QCoreApplication::quit);
                     QObject::connect(trayIcon, &QSystemTrayIcon::activated, [window](QSystemTrayIcon::ActivationReason reason) {
                         if (reason == QSystemTrayIcon::Trigger) {
                             window->setVisible(!window->isVisible());
                         }
                     });
                     
                     trayIcon->setContextMenu(trayMenu);
                     trayIcon->show();
                 }

                 QWidget *central = new QWidget();
                 QVBoxLayout *layout = new QVBoxLayout(central);

                 // Permission Warning
                 if (!has_permissions) {
                     QLabel *warn = new QLabel("<b>WARNING: Running without root permissions. Some connections may be hidden.</b>");
                     warn->setStyleSheet("QLabel { color: white; background-color: #d32f2f; padding: 5px; border-radius: 4px; }");
                     warn->setAlignment(Qt::AlignCenter);
                     layout->addWidget(warn);
                 }

                 // tcpdump-style filters
                 QHBoxLayout *filterLayout = new QHBoxLayout();

                 QLineEdit *hostFilter = new QLineEdit();
                 hostFilter->setPlaceholderText("Host (IP)");
                 hostFilter->setMaximumWidth(150);
                 filterLayout->addWidget(new QLabel("Host:"));
                 filterLayout->addWidget(hostFilter);

                 QLineEdit *portFilter = new QLineEdit();
                 portFilter->setPlaceholderText("Port");
                 portFilter->setMaximumWidth(100);
                 filterLayout->addWidget(new QLabel("Port:"));
                 filterLayout->addWidget(portFilter);

                 QLineEdit *protoFilter = new QLineEdit();
                 protoFilter->setPlaceholderText("TCP/UDP");
                 protoFilter->setMaximumWidth(100);
                 filterLayout->addWidget(new QLabel("Protocol:"));
                 filterLayout->addWidget(protoFilter);

                 QCheckBox *localhostCheck = new QCheckBox("Hide localhost");
                 filterLayout->addWidget(localhostCheck);

                 filterLayout->addStretch();
                 layout->addLayout(filterLayout);

                 // General text filter
                 QLineEdit *filter = new QLineEdit();
                 filter->setPlaceholderText("Filter by Name, PID or IP...");
                 layout->addWidget(filter);

                 // Table
                 QTableView *table = new QTableView();
                 std::cerr << "DEBUG: C++: creating RustTableModel" << std::endl;
                 RustTableModel *model = new RustTableModel(model_raw);
                 std::cerr << "DEBUG: C++: RustTableModel created" << std::endl;

                 // Sort Wrapper
                 NetMonSortProxy *proxy = new NetMonSortProxy();
                 proxy->setSourceModel(model);
                 proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
                 proxy->setFilterKeyColumn(-1); // Filter all columns

                 table->setModel(proxy);
                 table->setSortingEnabled(true);
                 
                 // Column Layout
                 QHeaderView *header = table->horizontalHeader();
                 header->setStretchLastSection(false); // Disable stretching the last column (Download)
                 
                 // Set specific resize modes
                 // 0: PID, 1: Process, 2: Command, 3: Proto, 4: Local, 5: Remote, 6: State, 7: Inode, 8: Up, 9: Down
                 header->setSectionResizeMode(QHeaderView::Interactive); // Default to interactive
                 header->resizeSection(2, 300);  // Command
                 
                 // Set initial widths instead of locking them with ResizeToContents
                 header->resizeSection(0, 60);  // PID
                 header->resizeSection(8, 100); // Upload
                 header->resizeSection(9, 100); // Download
                 
                 table->setSelectionBehavior(QAbstractItemView::SelectRows);
                 table->setAlternatingRowColors(true); // KDE integration hints

                 layout->addWidget(table);
                 window->setCentralWidget(central);

                 // Status bar for statistics (tcpdump-style)
                 QStatusBar *statusBar = new QStatusBar();
                 statusBar->showMessage("Connections: 0 | TCP: 0 | UDP: 0 | Upload: 0 B/s | Download: 0 B/s | Processes: 0");
                 window->setStatusBar(statusBar);

                 // Connect filter
                 QObject::connect(filter, &QLineEdit::textChanged, proxy, &QSortFilterProxyModel::setFilterFixedString);

                 // Timer for polling
                 QTimer *timer = new QTimer(window);
                 QObject::connect(timer, &QTimer::timeout, [=]() {
                     rust_poll_updates(self_ptr);
                 });
                 timer->start(500);

                 // Connect filters
                 auto updateFilter = [=]() {
                     std::string host = hostFilter->text().toStdString();
                     std::string port = portFilter->text().toStdString();
                     std::string proto = protoFilter->text().toStdString();
                     bool hideLocal = localhostCheck->isChecked();

                     rust_update_filter(
                         (void*)self_ptr,
                         host.c_str(),
                         port.c_str(),
                         proto.c_str(),
                         hideLocal
                     );
                 };

                 QObject::connect(hostFilter, &QLineEdit::textChanged, updateFilter);
                 QObject::connect(portFilter, &QLineEdit::textChanged, updateFilter);
                 QObject::connect(protoFilter, &QLineEdit::textChanged, updateFilter);
                 QObject::connect(localhostCheck, &QCheckBox::toggled, updateFilter);


                 window->show();
                 return std::make_pair((size_t)model, (size_t)statusBar);
             } catch (const std::exception& e) {
                 std::cerr << "Cpp Error in NetMonWindow::show: " << e.what() << std::endl;
                 return std::make_pair(0, 0);
             } catch (...) {
                 std::cerr << "Unknown Cpp Error in NetMonWindow::show" << std::endl;
                 return std::make_pair(0, 0);
             }
        })
    }
}

impl NetMonModel {
    fn row_count(&self) -> i32 {
        self.data.len() as i32
    }
    
    fn column_count(&self) -> i32 {
        10
    }
    
    fn data(&self, row: i32, col: i32, role: i32) -> QVariant {
        if row < 0 || row >= self.data.len() as i32 {
            return QVariant::default();
        }
        let item = &self.data[row as usize];

        // Qt::UserRole = 256. For sorting speeds numerically.
        if role == 256 {
             match col {
                8 => return QVariant::from(item.upload_speed),
                9 => return QVariant::from(item.download_speed),
                _ => return QVariant::default(),
             }
        }

        if role != 0 { // Qt::DisplayRole = 0
            return QVariant::default();
        }

        match col {
            0 => QVariant::from(item.pid.map(|p| p as i32).unwrap_or(0)),
            1 => QVariant::from(QString::from(item.process_name.clone())),
            2 => QVariant::from(QString::from(item.command_path.clone())),
            3 => QVariant::from(QString::from(item.protocol.clone())),
            4 => QVariant::from(QString::from(item.local_addr_display.clone())),
            5 => QVariant::from(QString::from(item.remote_addr_display.clone())),
            6 => QVariant::from(QString::from(item.state.clone())),
            7 => QVariant::from(item.inode),
            8 => QVariant::from(QString::from(format_speed(item.upload_speed))),
            9 => QVariant::from(QString::from(format_speed(item.download_speed))),
            _ => QVariant::default(),
        }
    }
    
    fn header_data(&self, col: i32) -> QVariant {
        let headers = ["PID", "Process", "Command", "Proto", "Local Addr", "Remote Addr", "State", "Inode", "Upload", "Download"];
        if col >= 0 && col < headers.len() as i32 {
             return QVariant::from(QString::from(headers[col as usize]));
        }
        QVariant::default()
    }
}

/// # Safety
///
/// This function is called from Qt C++ code and dereferences a raw pointer.
/// The caller must ensure:
/// - `obj` is a valid pointer to a NetMonModel instance
/// - `obj` remains valid for the duration of this call
/// - No concurrent mutation of the NetMonModel occurs during this call
#[no_mangle]
pub unsafe extern "C" fn rust_model_row_count(obj: *const NetMonModel) -> i32 {
    // SAFETY: Caller guarantees obj is valid
    let model = &*obj;
    model.row_count()
}

/// # Safety
///
/// This function is called from Qt C++ code and dereferences a raw pointer.
/// The caller must ensure:
/// - `obj` is a valid pointer to a NetMonModel instance
/// - `obj` remains valid for the duration of this call
/// - No concurrent mutation of the NetMonModel occurs during this call
#[no_mangle]
pub unsafe extern "C" fn rust_model_column_count(obj: *const NetMonModel) -> i32 {
    // SAFETY: Caller guarantees obj is valid
    let model = &*obj;
    model.column_count()
}

/// # Safety
///
/// This function is called from Qt C++ code and dereferences raw pointers.
/// The caller must ensure:
/// - `obj` is a valid pointer to a NetMonModel instance
/// - `result` is a valid pointer to a QVariant that can be written to
/// - Both pointers remain valid for the duration of this call
/// - No concurrent mutation of the NetMonModel occurs during this call
#[no_mangle]
pub unsafe extern "C" fn rust_model_data(obj: *const NetMonModel, row: i32, col: i32, role: i32, result: *mut QVariant) {
    // SAFETY: Caller guarantees obj is valid
    let model = &*obj;
    let val = model.data(row, col, role);
    // SAFETY: Caller guarantees result is valid and writable
    *result = val;
}

/// # Safety
///
/// This function is called from Qt C++ code and dereferences raw pointers.
/// The caller must ensure:
/// - `obj` is a valid pointer to a NetMonModel instance
/// - `result` is a valid pointer to a QVariant that can be written to
/// - Both pointers remain valid for the duration of this call
/// - No concurrent mutation of the NetMonModel occurs during this call
#[no_mangle]
pub unsafe extern "C" fn rust_model_header_data(obj: *const NetMonModel, col: i32, result: *mut QVariant) {
    // SAFETY: Caller guarantees obj is valid
    let model = &*obj;
    let val = model.header_data(col);
    // SAFETY: Caller guarantees result is valid and writable
    *result = val;
}

/// # Safety
///
/// This function is called from Qt C++ code and dereferences a raw pointer.
/// The caller must ensure:
/// - `obj` is a valid pointer to a NetMonWindow instance
/// - `obj` remains valid for the duration of this call
/// - The NetMonWindow is properly initialized with valid model_ptr and statusbar_ptr
#[no_mangle]
pub unsafe extern "C" fn rust_poll_updates(obj: *mut NetMonWindow) {
    // SAFETY: Caller guarantees obj is valid
    let window = &mut *obj;
    window.poll_updates();
}

/// # Safety
///
/// Called from Qt C++. Pointers must be valid strings or null.
/// `obj` must be a valid NetMonWindow pointer.
#[no_mangle]
pub unsafe extern "C" fn rust_update_filter(
    obj: *mut NetMonWindow,
    host: *const c_char,
    port: *const c_char,
    proto: *const c_char,
    hide_localhost: bool
) {
    let window = &mut *obj;
    
    let host_str = if host.is_null() { "".to_string() } else { CStr::from_ptr(host).to_string_lossy().to_string() };
    let port_str = if port.is_null() { "".to_string() } else { CStr::from_ptr(port).to_string_lossy().to_string() };
    let proto_str = if proto.is_null() { "".to_string() } else { CStr::from_ptr(proto).to_string_lossy().to_string() };
    
    let mut filter = ConnectionFilter::new();
    
    if !host_str.is_empty() {
        filter.host = Some(host_str);
    }
    
    if !port_str.is_empty() {
        if let Ok(p) = port_str.parse::<u16>() {
            filter.port = Some(p);
        }
    }
    
    if !proto_str.is_empty() {
        filter.protocol = Some(proto_str);
    }
    
    filter.filter_localhost = hide_localhost;
    // Keep default for show_closed for now, or add UI option later
    
    window.update_filter(filter);
}

pub struct NetMonWindow {
    pub model_data: Box<NetMonModel>,
    pub model_ptr: usize,
    pub statusbar_ptr: usize,
    pub receiver: Option<crossbeam_channel::Receiver<(Vec<ConnectionInfo>, NetworkStats)>>,
    pub filter_tx: Option<crossbeam_channel::Sender<ConnectionFilter>>,
    pub has_permissions: bool,
}

impl Default for NetMonWindow {
    fn default() -> Self {
        NetMonWindow {
            model_data: Box::new(NetMonModel { data: vec![] }),
            model_ptr: 0,
            statusbar_ptr: 0,
            receiver: None,
            filter_tx: None,
            has_permissions: false,
        }
    }
}

impl NetMonWindow {
    pub fn new(
        rx: crossbeam_channel::Receiver<(Vec<ConnectionInfo>, NetworkStats)>,
        filter_tx: crossbeam_channel::Sender<ConnectionFilter>,
        has_permissions: bool,
    ) -> Self {
        NetMonWindow {
            model_data: Box::new(NetMonModel { data: vec![] }),
            model_ptr: 0,
            statusbar_ptr: 0,
            receiver: Some(rx),
            filter_tx: Some(filter_tx),
            has_permissions,
        }
    }
    
    pub fn poll_updates(&mut self) {
        if let Some(rx) = &self.receiver {
            // Drain channel to get the latest update
            let mut latest = None;
            while let Ok(data) = rx.try_recv() {
                latest = Some(data);
            }
            if let Some((connections, stats)) = latest {
                self.update_data(connections);
                self.update_statusbar(&stats);
            }
        }
    }

    pub fn update_filter(&self, filter: ConnectionFilter) {
        if let Some(tx) = &self.filter_tx {
            let _ = tx.send(filter);
        }
    }

    fn update_statusbar(&self, stats: &NetworkStats) {
        if self.statusbar_ptr == 0 {
            return;
        }

        let msg = format!(
            "Connections: {} | TCP: {} | UDP: {} | Upload: {} | Download: {} | Processes: {}",
            stats.total_connections,
            stats.tcp_connections,
            stats.udp_connections,
            format_speed(stats.total_upload_speed),
            format_speed(stats.total_download_speed),
            stats.unique_processes
        );

        let statusbar_ptr = self.statusbar_ptr;
        update_statusbar_impl(statusbar_ptr, msg);
    }
    
    pub fn show(&mut self) {
        let model_raw = &*self.model_data as *const NetMonModel as usize;
        let self_ptr = self as *mut NetMonWindow as usize;

        let (model_ptr, statusbar_ptr) = create_window_impl(model_raw, self_ptr, self.has_permissions);

        self.model_ptr = model_ptr;
        self.statusbar_ptr = statusbar_ptr;
    }
    
    pub fn update_data(&mut self, new_data: Vec<ConnectionInfo>) {
        // SAFETY: Atomically swap data before signaling Qt to prevent race condition.
        // Qt's refresh() triggers callbacks to rust_model_data() which reads self.model_data.data.
        // By using std::mem::replace, we ensure the data is fully updated before Qt accesses it.
        let old_data = std::mem::replace(&mut self.model_data.data, new_data);
        drop(old_data); // Explicitly drop old data

        // NOW signal Qt - data is fully updated and ready to be read
        let model_cpp_ptr = self.model_ptr;
        if model_cpp_ptr != 0 {
            // SAFETY: model_cpp_ptr is a valid pointer to RustTableModel created in create_window_impl.
            // The pointer remains valid for the lifetime of NetMonWindow.
            unsafe {
                cpp::cpp!([model_cpp_ptr as "void*"] {
                    RustTableModel *model = (RustTableModel*)model_cpp_ptr;
                    model->refresh();
                });
            }
        }
    }
}

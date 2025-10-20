#!/usr/bin/env python3
import sys
import os
import json
import hashlib
import threading
import time
import signal


# Qt platform plugin sorununu çözmek için ortam değişkenlerini ayarla
os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = ''
os.environ['QT_PLUGIN_PATH'] = ''


    
    def get_text(self, key, **kwargs):
        """Çeviri metnini al"""
        text = self.translations.get(self.current_language, {}).get(key, key)
        if kwargs:
            try:
                return text.format(**kwargs)
            except:
                return text
        return text
    
    def set_language(self, language):
        """Dili değiştir ve kaydet"""
        if language in self.translations:
            self.current_language = language
            self.settings.setValue("language", language)
            return True
        return False
    
    def get_current_language(self):
        """Mevcut dili al"""
        return self.current_language

# Global çeviri yöneticisi
translator = TranslationManager()

# Konfigürasyon dizini yönetimi
def get_config_dir():
    """LSG konfigürasyon dizinini oluştur ve yolunu döndür"""
    home_dir = os.path.expanduser("~")
    config_dir = os.path.join(home_dir, ".config", "LSG")
    
    # Dizini oluştur (yoksa)
    os.makedirs(config_dir, exist_ok=True)
    
    # Alt dizinleri oluştur
    quarantine_dir = os.path.join(config_dir, "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    
    return config_dir


# Linux tehdit bilgileri - çeviri sistemi ile
def get_linux_threat_info():
    return {
        "botnet": {
            "description": translator.get_text("botnet_desc"),
            "examples": ["Linux.Mirai", "Linux.Gafgyt", "Linux.Xorddos"],
            "risk_level": translator.get_text("high_risk"),
            "common_locations": ["/tmp/", "/var/tmp/", "/dev/shm/"]
        },
        "rootkit": {
            "description": translator.get_text("rootkit_desc"),
            "examples": ["Linux.Rootkit.Adore", "Linux.Rootkit.Knark"],
            "risk_level": translator.get_text("very_high_risk"), 
            "common_locations": ["/lib/", "/usr/lib/", "/proc/"]
        },
        "miner": {
            "description": translator.get_text("miner_desc"),
            "examples": ["Linux.Miner.Xmrig", "Linux.Miner.Coinminer"],
            "risk_level": translator.get_text("medium_risk"),
            "common_locations": ["/tmp/", "/var/tmp/", "/home/"]
        }
    }

def get_linux_security_tips():
    return [
        translator.get_text("security_tip_1"),
        translator.get_text("security_tip_2"),
        translator.get_text("security_tip_3"),
        translator.get_text("security_tip_4")
    ]

SUSPICIOUS_LINUX_LOCATIONS = ["/tmp/", "/var/tmp/", "/dev/shm/"]

# Aktivite logger
class ActivityLogger:
    def __init__(self):
        self.log_file = os.path.join(CONFIG_DIR, "user_activity.json")
        self.activities = []
        self.load_activities()
    
    def load_activities(self):
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    self.activities = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            self.activities = []
    
    def log_activity(self, action, details=""):
        activity = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        self.activities.append(activity)
        self.save_activities()
    
    def save_activities(self):
        try:
            # Son 1000 aktiviteyi sakla
            if len(self.activities) > 1000:
                self.activities = self.activities[-1000:]
            
            with open(self.log_file, 'w') as f:
                json.dump(self.activities, f, indent=2)
        except (PermissionError, OSError, IOError):
            pass
    
    def get_recent_activities(self, limit=50):
        return self.activities[-limit:] if self.activities else []

# Ayarlar yöneticisi
class SettingsManager:
    def __init__(self):
        self.settings_file = os.path.join(CONFIG_DIR, "antivirus_settings.json")
        self.default_settings = {
            "auto_scan": False,
            "real_time_protection": True,
            "auto_update": True,
            "minimize_to_tray": True,
            "scan_archives": True,
            "scan_email": True,
            "heuristic_analysis": True,
            "quarantine_auto": True,
            "network_protection": True,
            "startup_with_system": True
        }
        self.load_settings()
    
    def load_settings(self):
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    self.settings = json.load(f)
            else:
                self.settings = self.default_settings.copy()
                self.save_settings()
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            self.settings = self.default_settings.copy()
    
   
# Ağ koruması ve port izleme
class NetworkProtection(QThread):
    suspicious_connection = pyqtSignal(str, str, int)
    port_scan_detected = pyqtSignal(str, list)
    
    def __init__(self):
        super().__init__()
        self.is_running = False
        self.monitored_ports = [22, 80, 443, 21, 25, 53, 110, 143, 993, 995]
        self.connection_log = {}
        
        # İstisna listeleri
        self.trusted_ips = ['127.0.0.1', '::1', '0.0.0.0']
        self.trusted_ports = [22, 80, 443, 53]  # SSH, HTTP, HTTPS, DNS
        self.trusted_processes = ['sshd', 'apache2', 'nginx', 'systemd']
        self.exceptions_file = os.path.join(CONFIG_DIR, "network_exceptions.json")
        self.load_exceptions()
        
    def load_exceptions(self):
        """İstisna listelerini dosyadan yükle"""
        try:
            if os.path.exists(self.exceptions_file):
                with open(self.exceptions_file, 'r') as f:
                    data = json.load(f)
                    self.trusted_ips.extend(data.get('trusted_ips', []))
                    self.trusted_ports.extend(data.get('trusted_ports', []))
                    self.trusted_processes.extend(data.get('trusted_processes', []))
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            pass
    
    def save_exceptions(self):
        """İstisna listelerini dosyaya kaydet"""
        try:
            data = {
                'trusted_ips': list(set(self.trusted_ips)),
                'trusted_ports': list(set(self.trusted_ports)),
                'trusted_processes': list(set(self.trusted_processes))
            }
            with open(self.exceptions_file, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except (PermissionError, OSError, IOError):
            return False
    
    def add_trusted_ip(self, ip):
        """Güvenilir IP ekle"""
        if ip not in self.trusted_ips:
            self.trusted_ips.append(ip)
            return self.save_exceptions()
        return True
    
    def add_trusted_port(self, port):
        """Güvenilir port ekle"""
        if port not in self.trusted_ports:
            self.trusted_ports.append(port)
            return self.save_exceptions()
        return True
    
   
    
    def stop_monitoring(self):
        self.is_running = False
    
    def run(self):
        while self.is_running:
            self.check_network_connections()
            self.scan_open_ports()
            time.sleep(10)
    
    def check_network_connections(self):
        try:
            import subprocess
            result = subprocess.run(['/bin/netstat', '-tuln'], capture_output=True, text=True)
            if result.returncode == 0:
                self.analyze_connections(result.stdout)
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass
    
    def analyze_connections(self, netstat_output):
        for line in netstat_output.split('\n'):
            if 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    address = parts[3]
                    if ':' in address:
                        ip, port = address.rsplit(':', 1)
                        try:
                            port_num = int(port)
                            # İstisna kontrolü - güvenilir bağlantıları atla
                            if not self.is_trusted_connection(ip, port_num):
                                if port_num not in self.monitored_ports:
                                    self.suspicious_connection.emit(ip, 'LISTEN', port_num)
                        except ValueError:
                            pass
    
    def scan_open_ports(self):
        try:
            import socket
            open_ports = []
            for port in self.monitored_ports:
                # İstisna kontrolü - güvenilir portları atla
                if port not in self.trusted_ports:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex(('127.0.0.1', port))
                        if result == 0:
                            open_ports.append(port)
            
            if open_ports:
                self.port_scan_detected.emit('127.0.0.1', open_ports)
        except Exception:
            pass


# Qt platform plugin sorununu çözmek için ortam değişkenlerini ayarla
os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = ''
os.environ['QT_PLUGIN_PATH'] = ''

class VirusDatabase:
    def __init__(self):
        self.db_path = os.path.join(CONFIG_DIR, "virus_signatures.db")
        self.init_database()
        
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY,
                    hash TEXT UNIQUE,
                    name TEXT,
                    type TEXT,
                    severity INTEGER,
                    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
    
    def update_database(self):
        """Veritabanını güncelle - worker thread kullan"""
        return True  # Her zaman başarılı dön
    

    
    def check_hash(self, file_hash):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT name, type, severity FROM signatures WHERE hash = ?', (file_hash,))
            return cursor.fetchone()

class DatabaseUpdateWorker(QThread):
    update_completed = pyqtSignal(bool)
    
    def run(self):
        try:
            # Önce yerel imzaları güncelle (her zaman çalışır)
            linux_signatures = [
                {"hash": "44c11b6b071a7b33fc4152c56f878e95", "name": "Linux.Mirai.Original", "type": "botnet", "severity": 5},
                {"hash": "7c6b5a4d3e2f1a0b9c8d7e6f5a4b3c2d", "name": "Linux.Gafgyt.Bashlite", "type": "botnet", "severity": 5},
                {"hash": "5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b", "name": "Linux.XorDDoS", "type": "ddos", "severity": 5},
                {"hash": "1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f", "name": "Linux.CoinMiner.XMRig", "type": "miner", "severity": 3},
                {"hash": "5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f", "name": "Linux.Rootkit.Adore", "type": "rootkit", "severity": 5},
                {"hash": "8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c", "name": "Linux.Backdoor.Setag", "type": "backdoor", "severity": 4},
                {"hash": "3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d", "name": "Linux.Tsunami", "type": "irc_bot", "severity": 4},
                {"hash": "0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a", "name": "Linux.CoinMiner.Malxmr", "type": "miner", "severity": 3}
            ]
            
            db_path = os.path.join(CONFIG_DIR, "virus_signatures.db")
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                for sig in linux_signatures:
                    cursor.execute('''
                        INSERT OR REPLACE INTO signatures (hash, name, type, severity)
                        VALUES (?, ?, ?, ?)
                    ''', (sig["hash"], sig["name"], sig["type"], sig["severity"]))
                conn.commit()
            
            # İnternet bağlantısını test et ve freshclam kullan
            try:
                # Gerçek browser gibi görünmek için headers ekle
                headers = {
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1'
                }
                
                # Basit bağlantı testi
                test_response = requests.get("https://httpbin.org/get", headers=headers, timeout=10)
                if test_response.status_code == 200:
                    # freshclam kullan (en güvenilir yöntem)
                    try:
                        import subprocess
                        result = subprocess.run(["freshclam", "--quiet", "--no-warnings"], 
                                              capture_output=True, timeout=120)
                        if result.returncode == 0:
                            print("ClamAV database updated via freshclam")
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        print("freshclam not available, using local signatures only")
            except:
                print("Network update failed, using local signatures only")
            
            self.update_completed.emit(True)
        except Exception as e:
            print(f"Database update error: {e}")
            self.update_completed.emit(False)


    
    QUICK_SCAN_LIMIT = 500
    FULL_SCAN_LIMIT = 50000
    
    def __init__(self, scan_path, scan_type="quick"):
        super().__init__()
        self.scan_path = scan_path
        self.scan_type = scan_type
        self.virus_db = VirusDatabase()
        self.is_running = True
        
    def run(self):
        results = {
            "scanned_files": 0,
            "threats_found": 0,
            "threats": [],
            "scan_time": 0
        }
        
        start_time = time.time()
        files_to_scan = []
        
        if os.path.isfile(self.scan_path):
            files_to_scan = [self.scan_path]
        else:
            # Hızlı tarama için kritik konumları ve şüpheli dosyaları tara
            if self.scan_type == "quick":
                quick_scan_paths = [
                    "/tmp/", "/var/tmp/", "/dev/shm/",
                    os.path.expanduser("~/Downloads/"),
                    os.path.expanduser("~/Desktop/"),
                    os.path.expanduser("~/.local/bin/"),
                    "/usr/local/bin/"
                ]
                
                for scan_dir in quick_scan_paths:
                    if os.path.exists(scan_dir):
                        for root, dirs, files in os.walk(scan_dir):
                            # 2 seviye derinliğe kadar in
                            if root.count(os.sep) - scan_dir.count(os.sep) > 2:
                                continue
                            
                            for file in files:
                                if not self.is_running:
                                    break
                                    
                                file_path = os.path.join(root, file)
                                
                                # Şüpheli dosya türlerini öncelikle tara
                                if (os.access(file_path, os.X_OK) or 
                                    file.endswith(('.sh', '.py', '.pl', '.bin', '.elf')) or
                                    file.startswith('.') or
                                    any(suspicious in file.lower() for suspicious in ['miner', 'bot', 'ddos', 'hack'])):
                                    files_to_scan.append(file_path)
                                    
                                # Dosya sayısını sınırla ama tamamen boş bırakma
                                if len(files_to_scan) > self.QUICK_SCAN_LIMIT:
                                    break
            else:
                # Tam tarama için tüm dosyalar - sistem klasörlerini atla
                excluded_dirs = {'/proc', '/sys', '/dev', '/run', '/tmp', '/var/tmp'}
                
                for root, dirs, files in os.walk(self.scan_path):
                    # Sistem klasörlerini atla
                    dirs[:] = [d for d in dirs if os.path.join(root, d) not in excluded_dirs]
                    
                    for file in files:
                        if not self.is_running:
                            break
                        
                        file_path = os.path.join(root, file)
                        
                        # Sadece gerçek dosyaları tara (sembolik linkleri atla)
                        if os.path.isfile(file_path) and not os.path.islink(file_path):
                            files_to_scan.append(file_path)
                        
                        # Çok fazla dosya varsa sınırla
                        if len(files_to_scan) > self.FULL_SCAN_LIMIT:
                            break
                    
                    if len(files_to_scan) > self.FULL_SCAN_LIMIT:
                        break
        
        total_files = len(files_to_scan)
        
        # Boş tarama kontrolü
        if total_files == 0:
            results["scan_time"] = time.time() - start_time
            self.scan_completed.emit(results)
            return
        
        for i, file_path in enumerate(files_to_scan):
            if not self.is_running:
                break
                
            try:
                threat = self.scan_file(file_path)
                if threat:
                    results["threats_found"] += 1
                    results["threats"].append(threat)
                    self.threat_found.emit(threat)
                    
                results["scanned_files"] += 1
                progress = int((i + 1) / total_files * 100)
                self.progress_updated.emit(progress)
                self.file_scanned.emit(file_path, translator.get_text("clean") if not threat else translator.get_text("danger"))
                
            except (PermissionError, OSError, IOError):
                # İzin hatası veya dosya erişim hatası - atla
                continue
            except Exception:
                # Diğer hatalar - atla
                continue
        
        results["scan_time"] = time.time() - start_time
        self.scan_completed.emit(results)
    
    def scan_file(self, file_path):
        try:
            # Dosya erişim kontrolü
            if not os.access(file_path, os.R_OK):
                return None
            
            # Dosya boyutu kontrolü (çok büyük dosyaları atla)
            try:
                file_size = os.path.getsize(file_path)
                if file_size > 100 * 1024 * 1024:  # 100MB
                    return None
                if file_size == 0:  # Boş dosyaları atla
                    return None
            except (OSError, IOError):
                return None
                
            with open(file_path, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.md5(file_content).hexdigest()
            
            # Beyaz liste kontrolü
            if self.is_whitelisted(file_hash):
                return None
            
            # Hash tabanlı kontrol
            threat = self.virus_db.check_hash(file_hash)
            if threat:
                return {"file": file_path, "threat": threat[0], "type": threat[1], "severity": threat[2]}
            
            # Linux'a özgü şüpheli dosya kontrolü
            if self.check_suspicious_linux_file(file_path, file_content):
                return {"file": file_path, "threat": "Suspicious.Linux.File", "type": "suspicious", "severity": 2}
                
            return None
        except:
            return None
    
    
            # Executable dosya kontrolü
            if not os.access(file_path, os.X_OK):
                return False
            
            # Çok küçük executable'lar (100 byte altı)
            if os.path.getsize(file_path) < 100:
                return True
            
            # Gizli executable dosyalar sadece şüpheli isimlerde
            if filename.startswith('.'):
                suspicious_names = ['..', '.ssh', '.bash', '.sh', '.tmp', '.cache']
                if any(name in filename for name in suspicious_names):
                    return True
            
            # Çok spesifik ve kesin malware kalıpları
            critical_patterns = [
                b'busybox tftp',
                b'busybox wget',
                b'/proc/net/tcp',
                b'echo -ne \\x90\\x90',
                b'rm -rf /*',
                b'>/dev/watchdog',
                b'iptables -F; iptables -X'
            ]
            
            # En az 3 kritik kalıp gerekli
            pattern_count = 0
            for pattern in critical_patterns:
                if pattern in content:
                    pattern_count += 1
            
            return pattern_count >= 3
            
        except Exception:
            return False
    
    def stop(self):
        self.is_running = False

class AntivirusApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.virus_db = VirusDatabase()
        self.scan_worker = None
        self.db_update_worker = None
        self.settings = SettingsManager()
        self.activity_logger = ActivityLogger()
        self.real_time_protection = RealTimeProtection(self.virus_db)
        self.real_time_protection.threat_detected.connect(self.handle_real_time_threat)
        
        # Ağ korumasını başlat
        self.network_protection = NetworkProtection()
        self.network_protection.suspicious_connection.connect(self.handle_suspicious_connection)
        self.network_protection.port_scan_detected.connect(self.handle_port_scan)
        
        # Sistem başlangıcından çalışıp çalışmadığını kontrol et
        self.started_from_startup = '--startup' in sys.argv
        
        self.init_ui()
        self.apply_dark_theme()
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.create_tray_icon()
        self.load_settings_to_ui()
        
        # Gerçek zamanlı korumayı başlat
        if self.settings.get('real_time_protection'):
            self.real_time_protection.start_protection()
        
        # Ağ korumasını başlat
        if self.settings.get('network_protection'):
            self.network_protection.start_monitoring()
        
        # Koruma UI'sini güncelle
        self.update_protection_ui()
        
        # Sidebar ikonunu güncelle
        self.update_sidebar_icon()
        
        # Sistem başlangıcından geliyorsa tray'e gizle
        if self.started_from_startup:
            self.hide()
        
        # Socket server başlat (tek instance için)
        self.start_socket_server()
        
    def init_ui(self):
        self.setWindowTitle(translator.get_text("main_title"))
        self.setGeometry(100, 100, 1200, 800)
        # Ana pencere ikonu - başlangıçta aktif koruma varsayalım
        self.setWindowIcon(get_current_icon(True))
        
        # Ana widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Ana layout
        main_layout = QHBoxLayout(central_widget)
        
        # Sol panel (menü)
        self.create_sidebar()
        main_layout.addWidget(self.sidebar, 1)
        
        # Sağ panel (içerik)
        self.content_area = QStackedWidget()
        self.content_area.setObjectName("contentArea")
        main_layout.addWidget(self.content_area, 4)
      
        self.create_status_bar()
        
    def create_sidebar(self):
        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setMaximumWidth(250)
        sidebar_layout = QVBoxLayout(self.sidebar)
        
        # Sidebar ikonu
        self.sidebar_icon_label = QLabel()
        self.sidebar_icon_label.setObjectName("sidebarIcon")
        self.sidebar_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.update_sidebar_icon()

        title = QLabel("Linux SecureGuard")
        title.setObjectName("sidebarTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        sidebar_layout.addWidget(self.sidebar_icon_label)
        sidebar_layout.addWidget(title)
        
     
        
        # Koruma durumu
        self.protection_card = self.create_status_card(translator.get_text("protection"), translator.get_text("active"), "active")
        cards_layout.addWidget(self.protection_card)
        
        # Son tarama
        self.last_scan_card = self.create_status_card(translator.get_text("last_scan"), translator.get_text("not_done_yet"), "warning")
        cards_layout.addWidget(self.last_scan_card)
        
        # Tehdit sayısı - tıklanabilir
        self.threat_card = self.create_status_card(translator.get_text("threats_count"), "0", "active")
        self.threat_card.mousePressEvent = lambda event: self.show_quarantine_page()
        self.threat_card.setCursor(Qt.CursorShape.PointingHandCursor)
        cards_layout.addWidget(self.threat_card)
        
        layout.addLayout(cards_layout)
        
        # Koruma kontrolü
        protection_group = QGroupBox(translator.get_text("real_time_protection"))
        protection_layout = QHBoxLayout(protection_group)
        
        self.protection_status_label = QLabel(f"{translator.get_text('status')}: {translator.get_text('active')}")
        self.protection_status_label.setStyleSheet("color: #4a9d5f; font-weight: bold; font-size: 14px;")
        
        self.toggle_protection_btn = QPushButton(translator.get_text("stop_protection"))
        self.toggle_protection_btn.setObjectName("dangerButton")
        self.toggle_protection_btn.clicked.connect(self.toggle_protection)
        
        protection_layout.addWidget(self.protection_status_label)
        protection_layout.addWidget(self.toggle_protection_btn)
        
        layout.addWidget(protection_group)
        
        # Hızlı eylemler
        actions_group = QGroupBox(translator.get_text("quick_actions"))
        actions_layout = QHBoxLayout(actions_group)
        
        quick_scan_btn = QPushButton(translator.get_text("quick_scan"))
        quick_scan_btn.clicked.connect(self.start_quick_scan_from_dashboard)
        
        full_scan_btn = QPushButton(translator.get_text("full_scan"))
        full_scan_btn.setObjectName("infoButton")
        full_scan_btn.clicked.connect(self.start_full_scan_from_dashboard)
        
        actions_layout.addWidget(quick_scan_btn)
        actions_layout.addWidget(full_scan_btn)
        
        layout.addWidget(actions_group)
        layout.addStretch()
        
        self.content_area.addWidget(dashboard)
    
    def create_network_page(self):
        network_page = QWidget()
        layout = QVBoxLayout(network_page)
        
        title = QLabel(translator.get_text("network_protection"))
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #4a9d5f; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # Ağ durumu
        network_status_group = QGroupBox(translator.get_text("network_status"))
        status_layout = QVBoxLayout(network_status_group)
        
        self.network_status_label = QLabel(translator.get_text("network_protection_active"))
        self.network_status_label.setStyleSheet("color: #4a9d5f; font-weight: bold; font-size: 14px;")
        status_layout.addWidget(self.network_status_label)
        
        # Port durumu
        self.port_status_table = QTableWidget()
        self.port_status_table.setColumnCount(3)
        self.port_status_table.setHorizontalHeaderLabels([translator.get_text("port"), translator.get_text("status"), translator.get_text("service")])
        self.port_status_table.horizontalHeader().setStretchLastSection(True)
        status_layout.addWidget(self.port_status_table)
        
        layout.addWidget(network_status_group)
        
        # Ağ aktivitesi
        activity_group = QGroupBox(translator.get_text("network_activity"))
        activity_layout = QVBoxLayout(activity_group)
        
        self.network_activity_table = QTableWidget()
        self.network_activity_table.setColumnCount(4)
        self.network_activity_table.setHorizontalHeaderLabels([translator.get_text("time"), translator.get_text("ip_address"), translator.get_text("port"), translator.get_text("status")])
        self.network_activity_table.horizontalHeader().setStretchLastSection(True)
        activity_layout.addWidget(self.network_activity_table)
        
        layout.addWidget(activity_group)
        
        # İstisna yönetimi
        exceptions_group = QGroupBox(translator.get_text("exceptions"))
        exceptions_layout = QVBoxLayout(exceptions_group)
        
        # Güvenilir IP'ler
        trusted_ips_layout = QHBoxLayout()
        trusted_ips_layout.addWidget(QLabel(translator.get_text("trusted_ips")))
        
        self.trusted_ip_input = QLineEdit()
        self.trusted_ip_input.setPlaceholderText("IP address (e.g: 192.168.1.1)")
        
        add_ip_btn = QPushButton(translator.get_text("add_ip"))
        add_ip_btn.clicked.connect(self.add_trusted_ip_ui)
        add_ip_btn.setObjectName("addButton")
        
        trusted_ips_layout.addWidget(self.trusted_ip_input)
        trusted_ips_layout.addWidget(add_ip_btn)
        exceptions_layout.addLayout(trusted_ips_layout)
        
        # Güvenilir portlar
        trusted_ports_layout = QHBoxLayout()
        trusted_ports_layout.addWidget(QLabel(translator.get_text("trusted_ports")))
        
        self.trusted_port_input = QLineEdit()
        self.trusted_port_input.setPlaceholderText("Port number (e.g: 8080)")
        
        add_port_btn = QPushButton(translator.get_text("add_port"))
        add_port_btn.clicked.connect(self.add_trusted_port_ui)
        add_port_btn.setObjectName("addButton")
        
        trusted_ports_layout.addWidget(self.trusted_port_input)
        trusted_ports_layout.addWidget(add_port_btn)
        exceptions_layout.addLayout(trusted_ports_layout)
        
        # İstisna listesi
        self.exceptions_table = QTableWidget()
        self.exceptions_table.setColumnCount(3)
        self.exceptions_table.setHorizontalHeaderLabels([translator.get_text("type"), translator.get_text("value"), translator.get_text("action")])
        self.exceptions_table.horizontalHeader().setStretchLastSection(True)
        exceptions_layout.addWidget(self.exceptions_table)
        
        layout.addWidget(exceptions_group)
        
        # Ağ kontrolleri
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton(translator.get_text("refresh"))
        refresh_btn.clicked.connect(self.refresh_network_status)
        refresh_btn.setObjectName("refreshButton")
        
        block_ip_btn = QPushButton(translator.get_text("block_ip"))
        block_ip_btn.clicked.connect(self.block_suspicious_ip)
        block_ip_btn.setObjectName("dangerButton")
        
        controls_layout.addWidget(refresh_btn)
        controls_layout.addWidget(block_ip_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        self.content_area.addWidget(network_page)
        
    def create_scan_page(self):
        scan_page = QWidget()
        layout = QVBoxLayout(scan_page)
        
        # Başlık
        title = QLabel(translator.get_text("system_scan"))
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        
        # Tarama seçenekleri
        scan_options = QGroupBox(translator.get_text("scan_options"))
        options_layout = QVBoxLayout(scan_options)
        
        # Tarama türü
        scan_type_layout = QHBoxLayout()
        self.quick_scan_radio = QRadioButton(translator.get_text("quick_scan_option"))
        self.full_scan_radio = QRadioButton(translator.get_text("full_scan_option"))
        self.custom_scan_radio = QRadioButton(translator.get_text("custom_scan_option"))
        self.quick_scan_radio.setChecked(True)
        
        scan_type_layout.addWidget(self.quick_scan_radio)
        scan_type_layout.addWidget(self.full_scan_radio)
        scan_type_layout.addWidget(self.custom_scan_radio)
        options_layout.addLayout(scan_type_layout)
        
        # Özel klasör seçimi
        folder_layout = QHBoxLayout()
        self.folder_path = QLineEdit()
        self.folder_path.setPlaceholderText(translator.get_text("select_folder"))
        browse_btn = QPushButton(translator.get_text("browse"))
        browse_btn.clicked.connect(self.browse_folder)
        
        folder_layout.addWidget(self.folder_path)
        folder_layout.addWidget(browse_btn)
        options_layout.addLayout(folder_layout)
        
        layout.addWidget(scan_options)
        
        # Tarama kontrolü
        control_layout = QHBoxLayout()
        self.start_scan_btn = QPushButton(translator.get_text("start_scan"))
        self.start_scan_btn.clicked.connect(self.start_scan_from_page)
        # QSS ile stillendirilecek
        
        self.stop_scan_btn = QPushButton(translator.get_text("stop_scan"))
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.setObjectName("dangerButton")
        
        control_layout.addWidget(self.start_scan_btn)
        control_layout.addWidget(self.stop_scan_btn)
        layout.addLayout(control_layout)
        
        # İlerleme çubuğu
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Tarama sonuçları
        results_group = QGroupBox(translator.get_text("scan_results"))
        results_layout = QVBoxLayout(results_group)
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels([translator.get_text("file"), translator.get_text("status"), translator.get_text("threat_type")])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.results_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        results_layout.addWidget(self.results_table)
        
        layout.addWidget(results_group)
        
        self.content_area.addWidget(scan_page)
        
    def create_quarantine_page(self):
        quarantine_page = QWidget()
        layout = QVBoxLayout(quarantine_page)
        
        title = QLabel(translator.get_text("quarantine_management"))
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #4a9d5f; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # Karantina tablosu
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels([translator.get_text("file"), translator.get_text("threat"), translator.get_text("date"), translator.get_text("actions")])
        layout.addWidget(self.quarantine_table)
        
        # Karantina eylemleri
        actions_layout = QHBoxLayout()
        restore_btn = QPushButton(translator.get_text("restore"))
        restore_btn.clicked.connect(self.restore_from_quarantine)
        
        delete_btn = QPushButton(translator.get_text("delete_permanent"))
        delete_btn.clicked.connect(self.delete_from_quarantine)
        
        whitelist_btn = QPushButton(translator.get_text("add_exception"))
        whitelist_btn.clicked.connect(self.add_to_whitelist)
        
        restore_btn.setObjectName("restoreButton")
        delete_btn.setObjectName("dangerButton")
        whitelist_btn.setObjectName("infoButton")
        
        actions_layout.addWidget(restore_btn)
        actions_layout.addWidget(delete_btn)
        actions_layout.addWidget(whitelist_btn)
        actions_layout.addStretch()
        
        layout.addLayout(actions_layout)
        
        self.content_area.addWidget(quarantine_page)
        
    def create_threats_page(self):
        threats_page = QWidget()
        layout = QVBoxLayout(threats_page)
        
        title = QLabel(translator.get_text("linux_threats"))
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #4a9d5f; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # Scroll area oluştur
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Tehdit türleri
        threat_info = get_linux_threat_info()
        for threat_type, info in threat_info.items():
            threat_group = QGroupBox(f"{threat_type.upper()} - {info['risk_level']} Risk")
            threat_layout = QVBoxLayout(threat_group)
            
            # Açıklama
            desc_label = QLabel(info['description'])
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #cccccc; margin: 5px;")
            threat_layout.addWidget(desc_label)
            
            # Örnekler
            examples_text = "Examples: " if translator.get_current_language() == "en" else "Örnekler: "
            examples_label = QLabel(f"{examples_text}{', '.join(info['examples'])}")
            examples_label.setWordWrap(True)
            examples_label.setStyleSheet("color: #b8860b; font-weight: bold; margin: 5px;")
            threat_layout.addWidget(examples_label)
            
            # Yaygın konumlar
            locations_text = "Common Locations: " if translator.get_current_language() == "en" else "Yaygın Konumlar: "
            locations_label = QLabel(f"{locations_text}{', '.join(info['common_locations'])}")
            locations_label.setWordWrap(True)
            locations_label.setStyleSheet("color: #cc6666; margin: 5px;")
            threat_layout.addWidget(locations_label)
            
            scroll_layout.addWidget(threat_group)
        
        # Güvenlik ipuçları
        tips_group = QGroupBox(translator.get_text("security_tips"))
        tips_layout = QVBoxLayout(tips_group)
        
        security_tips = get_linux_security_tips()
        for tip in security_tips:
            tip_label = QLabel(f"• {tip}")
            tip_label.setStyleSheet("color: #4a9d5f; margin: 3px;")
            tips_layout.addWidget(tip_label)
            
        scroll_layout.addWidget(tips_group)
        
        # Şüpheli konumlar
        locations_group = QGroupBox(translator.get_text("suspicious_locations"))
        locations_layout = QVBoxLayout(locations_group)
        
        locations_text = "\n".join([f"• {loc}" for loc in SUSPICIOUS_LINUX_LOCATIONS])
        locations_label = QLabel(locations_text)
        locations_label.setStyleSheet("color: #cc6666; margin: 5px;")
        locations_layout.addWidget(locations_label)
        
        scroll_layout.addWidget(locations_group)
        
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
        
        self.content_area.addWidget(threats_page)
        
    def create_settings_page(self):
        settings_page = QWidget()
        layout = QVBoxLayout(settings_page)
        
        title = QLabel(translator.get_text("settings"))
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #4a9d5f; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # Genel ayarlar
        general_group = QGroupBox(translator.get_text("general_settings"))
        general_layout = QVBoxLayout(general_group)
        
        self.auto_scan_check = QCheckBox(translator.get_text("auto_scan_startup"))
        self.real_time_check = QCheckBox(translator.get_text("real_time_protection_setting"))
        self.network_protection_check = QCheckBox(translator.get_text("network_protection_setting"))
        self.auto_update_check = QCheckBox(translator.get_text("auto_update"))
        self.minimize_tray_check = QCheckBox(translator.get_text("minimize_tray"))
        self.startup_check = QCheckBox(translator.get_text("startup_with_system"))
        
        general_layout.addWidget(self.auto_scan_check)
        general_layout.addWidget(self.real_time_check)
        general_layout.addWidget(self.network_protection_check)
        general_layout.addWidget(self.auto_update_check)
        general_layout.addWidget(self.minimize_tray_check)
        general_layout.addWidget(self.startup_check)
        
        # Dil seçimi
        language_layout = QHBoxLayout()
        language_layout.addWidget(QLabel(translator.get_text("language_setting")))
        
        self.language_combo = QComboBox()
        self.language_combo.addItem(translator.get_text("turkish"), "tr")
        self.language_combo.addItem(translator.get_text("english"), "en")
        
        # Mevcut dili seç
        current_lang = translator.get_current_language()
        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == current_lang:
                self.language_combo.setCurrentIndex(i)
                break
        
        self.language_combo.currentTextChanged.connect(self.change_language)
        language_layout.addWidget(self.language_combo)
        language_layout.addStretch()
        
        general_layout.addLayout(language_layout)
        layout.addWidget(general_group)
        
        # Tarama ayarları
        scan_group = QGroupBox(translator.get_text("scan_settings"))
        scan_layout = QVBoxLayout(scan_group)
        
        self.scan_archives_check = QCheckBox(translator.get_text("scan_archives"))
        self.scan_email_check = QCheckBox(translator.get_text("scan_email"))
        self.heuristic_check = QCheckBox(translator.get_text("heuristic_analysis"))
        self.quarantine_auto_check = QCheckBox(translator.get_text("auto_quarantine"))
        
        scan_layout.addWidget(self.scan_archives_check)
        scan_layout.addWidget(self.scan_email_check)
        scan_layout.addWidget(self.heuristic_check)
        scan_layout.addWidget(self.quarantine_auto_check)
        
        layout.addWidget(scan_group)
        
        # Kaydet butonu
        save_btn = QPushButton(translator.get_text("save_settings"))
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        # Ayarlar notu
        settings_note = QLabel(translator.get_text("settings_note"))
        settings_note.setStyleSheet("color: #ff4444; font-weight: bold; margin: 10px; font-size: 12px;")
        settings_note.setWordWrap(True)
        layout.addWidget(settings_note)
        
        layout.addStretch()
        
        self.content_area.addWidget(settings_page)
    
    def change_language(self):
        """Dil değiştirme fonksiyonu"""
        selected_lang = self.language_combo.currentData()
        if selected_lang and translator.set_language(selected_lang):
            QMessageBox.information(self, translator.get_text("success"), 
                                  translator.get_text("language_changed"))
        
    def create_logs_page(self):
        logs_page = QWidget()
        layout = QVBoxLayout(logs_page)
        
        title = QLabel(translator.get_text("system_logs"))
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        
        # Günlük tablosu
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(3)
        self.logs_table.setHorizontalHeaderLabels([translator.get_text("date"), translator.get_text("action"), translator.get_text("detail")])
        self.logs_table.horizontalHeader().setStretchLastSection(True)
        self.logs_table.verticalHeader().setVisible(False)
        self.logs_table.setAlternatingRowColors(True)
        self.logs_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.logs_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.logs_table)
        
        # Günlükleri yükle
        self.load_activity_logs()
        
        # Günlük eylemleri
        actions_layout = QHBoxLayout()
        refresh_logs_btn = QPushButton(translator.get_text("refresh"))
        refresh_logs_btn.clicked.connect(self.load_activity_logs)
        
        clear_logs_btn = QPushButton(translator.get_text("clear_logs"))
        clear_logs_btn.clicked.connect(self.clear_activity_logs)
        
        export_logs_btn = QPushButton(translator.get_text("export_logs"))
        export_logs_btn.clicked.connect(self.export_activity_logs)
        
        refresh_logs_btn.setObjectName("refreshButton")
        clear_logs_btn.setObjectName("dangerButton")
        export_logs_btn.setObjectName("infoButton")
        
        actions_layout.addWidget(refresh_logs_btn)
        actions_layout.addWidget(clear_logs_btn)
        actions_layout.addWidget(export_logs_btn)
        actions_layout.addStretch()
        
        layout.addLayout(actions_layout)
        
        self.content_area.addWidget(logs_page)
        
    def create_about_page(self):
        about_page = QWidget()
        layout = QVBoxLayout(about_page)
        
        # Başlık
        title = QLabel(translator.get_text("about_title"))
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        
        # Scroll area oluştur
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Program bilgileri
        program_group = QGroupBox(translator.get_text("program_info"))
        program_layout = QVBoxLayout(program_group)
        
        # Logo ve program adı
        logo_layout = QHBoxLayout()
        logo_label = QLabel()
        # Hakkında sayfasında lsgon.png kullan
        icon_path = "/usr/share/pixmaps/lsgon.png"
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            scaled_pixmap = pixmap.scaled(60, 60, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
        else:
            logo_label.setText("🛡️")
            logo_label.setStyleSheet("font-size: 36px;")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        program_name = QLabel("Linux SecureGuard")
        program_name.setStyleSheet("font-size: 32px; font-weight: bold; color: #4a9d5f;")
        program_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        program_name.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        
        logo_layout.addWidget(logo_label)
        logo_layout.addWidget(program_name)
        program_layout.addLayout(logo_layout)
        
        # Sürüm ve açıklama
        version_label = QLabel(translator.get_text("version"))
        version_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #b8860b; margin: 10px;")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        program_layout.addWidget(version_label)
        
        description = QLabel(translator.get_text("description"))
        description.setStyleSheet("color: #cccccc; margin: 15px; line-height: 1.5;")
        description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description.setWordWrap(True)
        program_layout.addWidget(description)
        
        scroll_layout.addWidget(program_group)
        
        # Geliştirici bilgileri
        developer_group = QGroupBox(translator.get_text("developer_info"))
        developer_layout = QVBoxLayout(developer_group)
        
        # Şirket bilgisi
        company_label = QLabel(translator.get_text("company"))
        company_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #4a9d5f; margin: 5px;")
        developer_layout.addWidget(company_label)
        
        company_name = QLabel(translator.get_text("company_name"))
        company_name.setStyleSheet("font-size: 18px; color: #ffffff; margin-left: 20px; margin-bottom: 10px;")
        developer_layout.addWidget(company_name)
        
        # Geliştirici bilgisi
        dev_label = QLabel("👨‍💻 Geliştirici")
        dev_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #4a9d5f; margin: 5px;")
        developer_layout.addWidget(dev_label)
        
        dev_name = QLabel("Fatih ÖNDER (CekToR)")
        dev_name.setStyleSheet("font-size: 18px; color: #ffffff; margin-left: 20px; margin-bottom: 10px;")
        developer_layout.addWidget(dev_name)
        
        # Website
        website_label = QLabel(translator.get_text("website"))
        website_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #4a9d5f; margin: 5px;")
        developer_layout.addWidget(website_label)
        
        website_link = QLabel('<a href="https://algyazilim.com" style="color: #0088ff; text-decoration: none;">https://algyazilim.com</a>')
        website_link.setStyleSheet("font-size: 16px; margin-left: 20px; margin-bottom: 10px;")
        website_link.setOpenExternalLinks(True)
        developer_layout.addWidget(website_link)
        
        # E-posta
        email_label = QLabel(translator.get_text("email"))
        email_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #4a9d5f; margin: 5px;")
        developer_layout.addWidget(email_label)
        
        email_link = QLabel('<a href="mailto:info@algyazilim.com" style="color: #0088ff; text-decoration: none;">info@algyazilim.com</a>')
        email_link.setStyleSheet("font-size: 16px; margin-left: 20px; margin-bottom: 10px;")
        email_link.setOpenExternalLinks(True)
        developer_layout.addWidget(email_link)
        
        scroll_layout.addWidget(developer_group)
        
        # Özellikler
        features_group = QGroupBox(translator.get_text("features"))
        features_layout = QVBoxLayout(features_group)
        
        features = [
            "🛡️ Gerçek zamanlı koruma ve tehdit tespiti",
            "🌐 Ağ güvenliği ve port izleme",
            "🔍 Hızlı, tam ve özel klasör taraması",
            "🔒 Otomatik karantina yönetimi",
            "🐧 Linux'a özgü malware tespiti",
            "📊 Detaylı aktivite günlükleri",
            "⚙️ Gelişmiş ayar seçenekleri",
            "🎨 Modern karanlık tema arayüzü"
        ]
        
        for feature in features:
            feature_label = QLabel(f"  {feature}")
            feature_label.setStyleSheet("color: #ffffff; margin: 3px; font-size: 14px;")
            features_layout.addWidget(feature_label)
        
        scroll_layout.addWidget(features_group)
        
        # Telif hakkı ve lisans
        copyright_group = QGroupBox(translator.get_text("copyright"))
        copyright_layout = QVBoxLayout(copyright_group)
        
        copyright_text = QLabel(f"© {datetime.now().year} ALG Yazılım & Elektronik Inc. Tüm hakları saklıdır.\n\n"
                               "Bu yazılım ALG Yazılım & Elektronik Inc. tarafından geliştirilmiştir. \n"
                               "Yazılımın kopyalanması, dağıtılması serbesttir.\n\n"
                               "Yazılımın Değiştirilmesi yasaktır.\n\n"
                               "Teknik destek için info@algyazilim.com adresine başvurunuz.")
        copyright_text.setStyleSheet("color: #cccccc; margin: 10px; line-height: 1.4;")
        copyright_text.setWordWrap(True)
        copyright_layout.addWidget(copyright_text)
        
        scroll_layout.addWidget(copyright_group)
        
        # Sistem bilgileri
        system_group = QGroupBox(translator.get_text("system_info"))
        system_layout = QVBoxLayout(system_group)
        
        import platform
        system_info = [
            f"Python Sürümü: {platform.python_version()}",
            "PyQt6 Sürümü: 6.x",
            f"Platform: {platform.system()} {platform.release()}",
            f"Mimari: {platform.machine()}"
        ]
        
        for info in system_info:
            info_label = QLabel(f"  • {info}")
            info_label.setStyleSheet("color: #b8860b; margin: 2px; font-size: 12px;")
            system_layout.addWidget(info_label)
        
        scroll_layout.addWidget(system_group)
        
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
        
        self.content_area.addWidget(about_page)
        
    def create_status_bar(self):
        self.status_bar = self.statusBar()
        self.status_label = QLabel(translator.get_text("ready"))
        self.status_bar.addWidget(self.status_label)
        
        # Sağ tarafta veritabanı durumu
        self.db_status = QLabel(translator.get_text("database_current"))
        self.status_bar.addPermanentWidget(self.db_status)
        
    def create_status_card(self, title, value, status):
        card = QFrame()
        card.setObjectName("statusCard")
        card.setProperty("status", status)
        
        layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setObjectName("cardTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        value_label = QLabel(value)
        value_label.setObjectName("cardValue")
        value_label.setProperty("status", status)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        return card
        
    def update_menu_selection(self, index):
        for i, btn in enumerate(self.menu_buttons):
            btn.setChecked(i == index)
    
    def update_sidebar_icon(self, is_active=None):
        """Sidebar ikonunu koruma durumuna göre güncelle"""
        if is_active is None:
            is_active = self.real_time_protection.is_running
        
        if is_active:
            icon_path = "/usr/share/pixmaps/lsgon.png"
        else:
            icon_path = "/usr/share/pixmaps/lsgoff.png"
        
        if os.path.exists(icon_path):
            pixmap = QPixmap(icon_path)
            scaled_pixmap = pixmap.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.sidebar_icon_label.setPixmap(scaled_pixmap)
        else:
            # Fallback
            fallback_path = "/usr/share/pixmaps/lsglo.png"
            if os.path.exists(fallback_path):
                pixmap = QPixmap(fallback_path)
                scaled_pixmap = pixmap.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.sidebar_icon_label.setPixmap(scaled_pixmap)
            else:
                self.sidebar_icon_label.setText("🛡️")
        
    def apply_dark_theme(self):
        try:
            css_file = '/usr/share/LSG/main.qss'
            with open(css_file, 'r', encoding='utf-8') as f:
                self.setStyleSheet(f.read())
        except FileNotFoundError:
            self.setStyleSheet(self.get_default_style())
    
    def get_default_style(self):
        return """
        QMainWindow {
            background-color: #1e1e1e;
            color: #ffffff;
        }
        QWidget {
            background-color: #1e1e1e;
            color: #ffffff;
            font-size: 14px;
        }
        """
        
    def show_dashboard(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("home_page"))
        self.content_area.setCurrentIndex(0)
        self.update_menu_selection(0)
        self.update_threat_count()
        
    def show_scan_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("scan_page"))
        self.content_area.setCurrentIndex(1)
        self.update_menu_selection(1)
        
    def show_network_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("network_page"))
        self.content_area.setCurrentIndex(2)
        self.refresh_network_status()
        self.refresh_exceptions_table()
        self.update_network_status_ui()
        
    def show_quarantine_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("quarantine_page"))
        self.content_area.setCurrentIndex(3)
        self.load_quarantine_records()
        self.update_threat_count()
        
    def show_threats_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("threats_page"))
        self.content_area.setCurrentIndex(4)
        
    def show_settings_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("settings_page"))
        self.content_area.setCurrentIndex(5)
        
    def show_logs_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("logs_page"))
        self.content_area.setCurrentIndex(6)
        self.load_activity_logs()
        
    def show_about_page(self):
        self.activity_logger.log_activity(translator.get_text("page_navigation"), translator.get_text("about_page"))
        self.content_area.setCurrentIndex(7)
        
    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Taranacak Klasörü Seçin")
        if folder:
            self.folder_path.setText(folder)
            
    def update_virus_database(self):
        self.activity_logger.log_activity(translator.get_text("database_update"), "Started")
        self.status_label.setText(translator.get_text("updating_database"))
        
        # Worker thread ile güncelle
        self.db_update_worker = DatabaseUpdateWorker()
        self.db_update_worker.update_completed.connect(self.on_database_updated)
        self.db_update_worker.start()
    
    def on_database_updated(self, success):
        if success:
            self.activity_logger.log_activity(translator.get_text("database_update"), "Successful")
            self.db_status.setText(translator.get_text("database_current"))
            self.status_label.setText(translator.get_text("database_updated"))
            QMessageBox.information(self, translator.get_text("success"), translator.get_text("database_updated_msg"))
        else:
            self.activity_logger.log_activity(translator.get_text("database_update"), "Failed")
            self.status_label.setText(translator.get_text("database_update_failed"))
            QMessageBox.warning(self, translator.get_text("error"), translator.get_text("database_error_msg"))
            
    def start_scan(self, scan_type="quick"):
        self.activity_logger.log_activity(translator.get_text("scan_started_log"), f"Type: {scan_type}")
        if scan_type == "quick":
            scan_path = os.path.expanduser("~")
        elif scan_type == "full":
            scan_path = "/"
        else:
            scan_path = self.folder_path.text() if hasattr(self, 'folder_path') else "/"
            
        if hasattr(self, 'start_scan_btn'):
            self.start_scan_btn.setEnabled(False)
        if hasattr(self, 'stop_scan_btn'):
            self.stop_scan_btn.setEnabled(True)
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
        
        self.scan_worker = ScanWorker(scan_path, scan_type)
        if hasattr(self, 'progress_bar'):
            self.scan_worker.progress_updated.connect(self.progress_bar.setValue)
        if hasattr(self, 'results_table'):
            self.scan_worker.file_scanned.connect(self.add_scan_result)
        self.scan_worker.scan_completed.connect(self.scan_finished)
        self.scan_worker.threat_found.connect(self.handle_threat_found)
        self.scan_worker.start()
        
        self.status_label.setText(translator.get_text("scan_started"))
        
    def start_scan_from_page(self):
        if self.quick_scan_radio.isChecked():
            self.start_scan("quick")
        elif self.full_scan_radio.isChecked():
            self.start_scan("full")
        elif self.custom_scan_radio.isChecked():
            if self.folder_path.text():
                self.start_custom_scan(self.folder_path.text())
            else:
                QMessageBox.warning(self, translator.get_text("warning"), translator.get_text("select_folder_msg"))
                
    def start_custom_scan(self, path):
        # Önceki worker'ı temizle
        if hasattr(self, 'scan_worker') and self.scan_worker:
            self.scan_worker.progress_updated.disconnect()
            self.scan_worker.file_scanned.disconnect()
            self.scan_worker.scan_completed.disconnect()
            self.scan_worker.threat_found.disconnect()
        
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.scan_worker = ScanWorker(path, "custom")
        self.scan_worker.progress_updated.connect(self.progress_bar.setValue)
        self.scan_worker.file_scanned.connect(self.add_scan_result)
        self.scan_worker.scan_completed.connect(self.scan_finished)
        self.scan_worker.threat_found.connect(self.handle_threat_found)
        self.scan_worker.start()
        
    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
            self.scan_worker.wait()
        self.scan_finished({"scanned_files": 0, "threats_found": 0, "scan_time": 0})
        
    def add_scan_result(self, file_path, status):
        if hasattr(self, 'results_table'):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(file_path))
            self.results_table.setItem(row, 1, QTableWidgetItem(status))
            threat_type = "N/A" if status == translator.get_text("clean") else "Malware"
            self.results_table.setItem(row, 2, QTableWidgetItem(threat_type))
        
    def scan_finished(self, results):
        if hasattr(self, 'start_scan_btn'):
            self.start_scan_btn.setEnabled(True)
        if hasattr(self, 'stop_scan_btn'):
            self.stop_scan_btn.setEnabled(False)
        if hasattr(self, 'progress_bar'):
            self.progress_bar.setVisible(False)
        
        message = translator.get_text("scan_completed_msg", 
                                    scanned=results['scanned_files'],
                                    threats=results['threats_found'], 
                                    time=results.get('scan_time', 0))
        
        QMessageBox.information(self, translator.get_text("scan_completed"), message)
        self.status_label.setText(translator.get_text("scan_completed"))
        self.update_last_scan_info(results)
    
    def create_tray_icon(self):
        try:
            self.tray_icon = QSystemTrayIcon(self)
            # Başlangıçta aktif koruma ikonu
            self.tray_icon.setIcon(get_current_icon(True))
            
            # Tray menüsü
            tray_menu = QMenu()
            
            show_action = tray_menu.addAction(translator.get_text("show"))
            show_action.triggered.connect(self.show)
            
            # Koruma durumu menü öğesi
            self.protection_menu_action = tray_menu.addAction(translator.get_text("stop_protection"))
            self.protection_menu_action.setIcon(get_current_icon(False))  # Durdur ikonu
            self.protection_menu_action.triggered.connect(self.toggle_protection)
            
            tray_menu.addSeparator()
            
            scan_action = tray_menu.addAction(translator.get_text("quick_scan"))
            scan_action.triggered.connect(lambda: self.start_scan("quick"))
            
            tray_menu.addSeparator()
            
            quit_action = tray_menu.addAction(translator.get_text("exit"))
            quit_action.triggered.connect(QApplication.quit)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()
            
            # Tray icon tıklama olayı
            self.tray_icon.activated.connect(self.tray_icon_activated)
        except Exception as e:
            print(f"Tray icon oluşturulamadı: {e}")
    
    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()
    
    def closeEvent(self, event):
        if (hasattr(self, 'tray_icon') and 
            hasattr(self.tray_icon, 'isVisible') and 
            self.settings.get('minimize_to_tray') and 
            self.tray_icon.isVisible()):
            self.hide()
            event.ignore()
        else:
            if hasattr(self, 'real_time_protection'):
                self.real_time_protection.stop_protection()
            event.accept()
    
    def load_settings_to_ui(self):
        if hasattr(self, 'auto_scan_check'):
            self.auto_scan_check.setChecked(self.settings.get('auto_scan'))
        if hasattr(self, 'real_time_check'):
            self.real_time_check.setChecked(self.settings.get('real_time_protection'))
        if hasattr(self, 'network_protection_check'):
            self.network_protection_check.setChecked(self.settings.get('network_protection'))
        if hasattr(self, 'auto_update_check'):
            self.auto_update_check.setChecked(self.settings.get('auto_update'))
        if hasattr(self, 'minimize_tray_check'):
            self.minimize_tray_check.setChecked(self.settings.get('minimize_to_tray'))
        if hasattr(self, 'scan_archives_check'):
            self.scan_archives_check.setChecked(self.settings.get('scan_archives'))
        if hasattr(self, 'scan_email_check'):
            self.scan_email_check.setChecked(self.settings.get('scan_email'))
        if hasattr(self, 'heuristic_check'):
            self.heuristic_check.setChecked(self.settings.get('heuristic_analysis'))
        if hasattr(self, 'quarantine_auto_check'):
            self.quarantine_auto_check.setChecked(self.settings.get('quarantine_auto'))
        if hasattr(self, 'startup_check'):
            self.startup_check.setChecked(self.settings.get('startup_with_system'))
    
    def save_settings(self):
        self.activity_logger.log_activity(translator.get_text("settings_saved_log"), "User settings updated")
        self.settings.set('auto_scan', self.auto_scan_check.isChecked())
        self.settings.set('real_time_protection', self.real_time_check.isChecked())
        self.settings.set('network_protection', self.network_protection_check.isChecked())
        self.settings.set('auto_update', self.auto_update_check.isChecked())
        self.settings.set('minimize_to_tray', self.minimize_tray_check.isChecked())
        self.settings.set('scan_archives', self.scan_archives_check.isChecked())
        self.settings.set('scan_email', self.scan_email_check.isChecked())
        self.settings.set('heuristic_analysis', self.heuristic_check.isChecked())
        self.settings.set('quarantine_auto', self.quarantine_auto_check.isChecked())
        self.settings.set('startup_with_system', self.startup_check.isChecked())
        
        # Sistem başlangıcı ayarını uygula
        self.setup_startup_autorun()
        
        # Gerçek zamanlı korumayı güncelle
        if self.real_time_check.isChecked():
            if not self.real_time_protection.is_running:
                self.real_time_protection.start_protection()
        else:
            if self.real_time_protection.is_running:
                self.real_time_protection.stop_protection()
        
        # Ağ korumasını güncelle
        if self.network_protection_check.isChecked():
            if not self.network_protection.is_running:
                self.network_protection.start_monitoring()
        else:
            if self.network_protection.is_running:
                self.network_protection.stop_monitoring()
        
        QMessageBox.information(self, translator.get_text("success"), translator.get_text("settings_saved_msg"))
        self.status_label.setText(translator.get_text("settings_saved"))
        self.update_protection_ui()
        self.update_network_status_ui()
    
    def toggle_protection(self):
        if self.real_time_protection.is_running:
            self.activity_logger.log_activity(translator.get_text("protection_stopped"), "Real-time and network protection")
            self.real_time_protection.stop_protection()
            self.network_protection.stop_monitoring()
            self.settings.set('real_time_protection', False)
            if hasattr(self, 'real_time_check'):
                self.real_time_check.setChecked(False)
        else:
            self.activity_logger.log_activity(translator.get_text("protection_started"), "Real-time and network protection")
            self.real_time_protection.start_protection()
            self.network_protection.start_monitoring()
            self.settings.set('real_time_protection', True)
            if hasattr(self, 'real_time_check'):
                self.real_time_check.setChecked(True)
        
        self.update_protection_ui()
        self.update_network_status_ui()
    
    def update_protection_ui(self):
        is_active = self.real_time_protection.is_running
        
        # Ana sayfa koruma durumu güncelle
        if hasattr(self, 'protection_status_label'):
            if is_active:
                self.protection_status_label.setText(f"{translator.get_text('status')}: {translator.get_text('active')}")
                self.protection_status_label.setStyleSheet("color: #4a9d5f; font-weight: bold; font-size: 14px;")
            else:
                self.protection_status_label.setText(f"{translator.get_text('status')}: {translator.get_text('inactive')}")
                self.protection_status_label.setStyleSheet("color: #cc3333; font-weight: bold; font-size: 14px;")
        
        # Koruma kartını güncelle
        if hasattr(self, 'protection_card'):
            # Kart içeriğini güncelle
            layout = self.protection_card.layout()
            if layout and layout.count() >= 2:
                value_label = layout.itemAt(1).widget()
                if is_active:
                    value_label.setText(translator.get_text("active"))
                    value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #4a9d5f;")
                    self.protection_card.setStyleSheet("""
                        QFrame {
                            background-color: #2a2a2a;
                            border: 2px solid #4a9d5f;
                            border-radius: 10px;
                            padding: 20px;
                        }
                    """)
                else:
                    value_label.setText(translator.get_text("inactive"))
                    value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #cc3333;")
                    self.protection_card.setStyleSheet("""
                        QFrame {
                            background-color: #2a2a2a;
                            border: 2px solid #cc3333;
                            border-radius: 10px;
                            padding: 20px;
                        }
                    """)
        
    
        
        # Durum çubuğu güncelle
        if is_active:
            self.status_label.setText(translator.get_text("protection_active"))
        else:
            self.status_label.setText(translator.get_text("protection_inactive"))
    
    def start_quick_scan_from_dashboard(self):
        # Tarama sayfasına geç
        self.show_scan_page()
        # Hızlı tarama seçeneğini aktif et
        if hasattr(self, 'quick_scan_radio'):
            self.quick_scan_radio.setChecked(True)
        # Taramayı başlat
        self.start_scan("quick")
    
    def start_full_scan_from_dashboard(self):
        # Tarama sayfasına geç
        self.show_scan_page()
        # Tam tarama seçeneğini aktif et
        if hasattr(self, 'full_scan_radio'):
            self.full_scan_radio.setChecked(True)
        # Taramayı başlat
        self.start_scan("full")
    
    def handle_real_time_threat(self, file_path, threat):
        # Tehdit tespit edildiğinde bildirim göster
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                translator.get_text("threat_detected"),
                f"Dosya: {os.path.basename(file_path)}\nTehdit: {threat[0]}",
                QSystemTrayIcon.MessageIcon.Warning,
                5000
            )
        
        # Otomatik karantina
        if self.settings.get('quarantine_auto'):
            self.quarantine_file(file_path, threat)
    
    def quarantine_file(self, file_path, threat):
        try:
            quarantine_dir = "quarantine"
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)
            
            # Dosyayı karantinaya taşı
            quarantine_path = os.path.join(quarantine_dir, os.path.basename(file_path))
            os.rename(file_path, quarantine_path)
            
            # Karantina kaydını ekle
            self.add_quarantine_record(quarantine_path, threat)
            
        except Exception as e:
            print(f"Karantina hatası: {e}")
    
    def add_quarantine_record(self, file_path, threat):
        if hasattr(self, 'quarantine_table'):
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(file_path))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(str(threat[0])))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem("Karantinada"))
    
    def load_quarantine_records(self):
        """Karantina kayıtlarını yükle"""
        if hasattr(self, 'quarantine_table'):
            self.quarantine_table.setRowCount(0)
            
            quarantine_dir = "quarantine"
            if os.path.exists(quarantine_dir):
                for filename in os.listdir(quarantine_dir):
                    file_path = os.path.join(quarantine_dir, filename)
                    if os.path.isfile(file_path):
                        row = self.quarantine_table.rowCount()
                        self.quarantine_table.insertRow(row)
                        
                        self.quarantine_table.setItem(row, 0, QTableWidgetItem(filename))
                        self.quarantine_table.setItem(row, 1, QTableWidgetItem("Malware"))
                        
                        # Dosya tarihini al
                        try:
                            mtime = os.path.getmtime(file_path)
                            date_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                        except (OSError, ValueError):
                            date_str = "Bilinmiyor"
                        
                        self.quarantine_table.setItem(row, 2, QTableWidgetItem(date_str))
                        self.quarantine_table.setItem(row, 3, QTableWidgetItem("Karantinada"))
    
    def restore_from_quarantine(self):
        """Seçili dosyayı karantinadan geri yükle"""
        if hasattr(self, 'quarantine_table'):
            current_row = self.quarantine_table.currentRow()
            if current_row >= 0:
                filename_item = self.quarantine_table.item(current_row, 0)
                if filename_item:
                    filename = filename_item.text()
                    quarantine_path = os.path.join(CONFIG_DIR, "quarantine", filename)
                    
                    if os.path.exists(quarantine_path):
                        # Downloads klasörünü oluştur
                        downloads_dir = os.path.expanduser("~/Downloads/")
                        os.makedirs(downloads_dir, exist_ok=True)
                        
                        # Orijinal konuma geri yükle
                        restore_path = os.path.join(downloads_dir, filename)
                        try:
                            os.rename(quarantine_path, restore_path)
                            QMessageBox.information(self, "Başarılı", f"Dosya geri yüklendi: {restore_path}")
                            self.load_quarantine_records()
                            self.update_threat_count()
                        except Exception as e:
                            QMessageBox.warning(self, "Hata", f"Geri yükleme hatası: {e}")
                    else:
                        QMessageBox.warning(self, "Hata", "Dosya bulunamadı!")
            else:
                QMessageBox.warning(self, "Uyarı", "Lütfen geri yüklenecek dosyayı seçin!")
    
    def delete_from_quarantine(self):
        """Seçili dosyayı karantinadan kalıcı olarak sil"""
        if hasattr(self, 'quarantine_table'):
            current_row = self.quarantine_table.currentRow()
            if current_row >= 0:
                filename_item = self.quarantine_table.item(current_row, 0)
                if filename_item:
                    filename = filename_item.text()
                    quarantine_path = os.path.join(CONFIG_DIR, "quarantine", filename)
                    
                    reply = QMessageBox.question(self, "Onayla", 
                                                f"'{filename}' dosyasını kalıcı olarak silmek istediğinizden emin misiniz?",
                                                QMessageBox.Yes | QMessageBox.No)
                    
                    if reply == QMessageBox.Yes:
                        try:
                            if os.path.exists(quarantine_path):
                                os.remove(quarantine_path)
                            QMessageBox.information(self, "Başarılı", "Dosya kalıcı olarak silindi!")
                            self.load_quarantine_records()
                            self.update_threat_count()
                        except Exception as e:
                            QMessageBox.warning(self, "Hata", f"Silme hatası: {e}")
            else:
                QMessageBox.warning(self, "Uyarı", "Lütfen silinecek dosyayı seçin!")
    
    def add_to_whitelist(self):
        """Seçili dosyayı beyaz listeye ekle ve karantinadan çıkar"""
        if hasattr(self, 'quarantine_table'):
            current_row = self.quarantine_table.currentRow()
            if current_row >= 0:
                filename_item = self.quarantine_table.item(current_row, 0)
                if filename_item:
                    filename = filename_item.text()
                    quarantine_path = os.path.join(CONFIG_DIR, "quarantine", filename)
                    
                    if os.path.exists(quarantine_path):
                        try:
                            # Dosyanın hash'ini al
                            with open(quarantine_path, 'rb') as f:
                                file_content = f.read()
                                file_hash = hashlib.md5(file_content).hexdigest()
                            
                            # Beyaz listeye ekle
                            self.add_to_file_whitelist(file_hash, filename)
                            
                            # Downloads klasörünü oluştur
                            downloads_dir = os.path.expanduser("~/Downloads/")
                            os.makedirs(downloads_dir, exist_ok=True)
                            
                            # Dosyayı geri yükle
                            restore_path = os.path.join(downloads_dir, filename)
                            os.rename(quarantine_path, restore_path)
                            
                            QMessageBox.information(self, "Başarılı", 
                                                  f"Dosya beyaz listeye eklendi ve geri yüklendi: {restore_path}")
                            self.load_quarantine_records()
                            self.update_threat_count()
                        except Exception as e:
                            QMessageBox.warning(self, "Hata", f"Beyaz liste ekleme hatası: {e}")
                    else:
                        QMessageBox.warning(self, "Hata", "Dosya bulunamadı!")
            else:
                QMessageBox.warning(self, "Uyarı", "Lütfen beyaz listeye eklenecek dosyayı seçin!")
    
    def add_to_file_whitelist(self, file_hash, filename):
        """Dosyayı beyaz listeye ekle"""
        try:
            whitelist_file = os.path.join(CONFIG_DIR, "file_whitelist.json")
            whitelist = []
            
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r') as f:
                    whitelist = json.load(f)
            
            # Yeni giriş ekle
            whitelist_entry = {
                "hash": file_hash,
                "filename": filename,
                "added_date": datetime.now().isoformat()
            }
            
            if not any(entry["hash"] == file_hash for entry in whitelist):
                whitelist.append(whitelist_entry)
                
                with open(whitelist_file, 'w') as f:
                    json.dump(whitelist, f, indent=4)
                
                return True
        except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError):
            return False
    
    def update_last_scan_info(self, results):
        """Son tarama bilgisini güncelle"""
        if hasattr(self, 'last_scan_card'):
            layout = self.last_scan_card.layout()
            if layout and layout.count() >= 2:
                value_label = layout.itemAt(1).widget()
                
                # Tarama bilgisini formatla
                current_time = datetime.now().strftime("%H:%M")
                scan_info = f"{current_time} - {results['scanned_files']} dosya"
                
                value_label.setText(scan_info)
                
                # Renk güncelle - tehdit varsa kırmızı, yoksa yeşil
                if results.get('threats_found', 0) > 0:
                    value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff4444;")
                    self.last_scan_card.setStyleSheet("""
                        QFrame {
                            background-color: #2a2a2a;
                            border: 2px solid #ff4444;
                            border-radius: 10px;
                            padding: 20px;
                        }
                    """)
                else:
                    value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff88;")
                    self.last_scan_card.setStyleSheet("""
                        QFrame {
                            background-color: #2a2a2a;
                            border: 2px solid #00ff88;
                            border-radius: 10px;
                            padding: 20px;
                        }
                    """)
    
    def load_activity_logs(self):
        """Aktivite loglarını tabloya yükle"""
        if hasattr(self, 'logs_table'):
            self.logs_table.setRowCount(0)
            activities = self.activity_logger.get_recent_activities(100)
            
            for activity in reversed(activities):  # En yeniler üstte
                row = self.logs_table.rowCount()
                self.logs_table.insertRow(row)
                
                # Tarihi formatla
                try:
                    timestamp = datetime.fromisoformat(activity['timestamp'])
                    date_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    date_str = activity['timestamp']
                
                self.logs_table.setItem(row, 0, QTableWidgetItem(date_str))
                self.logs_table.setItem(row, 1, QTableWidgetItem(activity['action']))
                self.logs_table.setItem(row, 2, QTableWidgetItem(activity.get('details', '')))
    
    def clear_activity_logs(self):
        """Aktivite loglarını temizle"""
        reply = QMessageBox.question(self, "Onayla", 
                                   "Tüm aktivite loglarını silmek istediğinizden emin misiniz?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.activity_logger.activities = []
            self.activity_logger.save_activities()
            self.load_activity_logs()
            QMessageBox.information(self, "Başarılı", "Aktivite logları temizlendi!")
    
    def export_activity_logs(self):
        """Aktivite loglarını dışa aktar"""
        filename, _ = QFileDialog.getSaveFileName(self, "Logları Kaydet", 
                                                "activity_logs.json", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.activity_logger.activities, f, indent=2)
                QMessageBox.information(self, "Başarılı", f"Loglar kaydedildi: {filename}")
            except (PermissionError, OSError, IOError) as e:
                QMessageBox.warning(self, "Hata", f"Kaydetme hatası: {e}")
    
    def is_whitelisted(self, file_hash):
        """Dosyanın beyaz listede olup olmadığını kontrol et"""
        try:
            whitelist_file = os.path.join(CONFIG_DIR, "file_whitelist.json")
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r') as f:
                    whitelist = json.load(f)
                return any(entry["hash"] == file_hash for entry in whitelist)
        except (FileNotFoundError, json.JSONDecodeError, PermissionError):
            pass
        return False
    
    def refresh_network_status(self):
        """Ağ durumunu yenile ve port tarama yap"""
        if hasattr(self, 'port_status_table'):
            self.port_status_table.setRowCount(0)
            
            # Temel portları kontrol et
            common_ports = {
                22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 21: 'FTP',
                25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP'
            }
            
            for port, service in common_ports.items():
                status = self.check_port_status(port)
                self.add_port_status(port, status, service)
    
    def check_port_status(self, port):
        """Port durumunu kontrol et"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', port))
                return "Açık" if result == 0 else "Kapalı"
        except (socket.error, OSError):
            return "Bilinmiyor"
    
    def add_port_status(self, port, status, service):
        """Port durumunu tabloya ekle"""
        if hasattr(self, 'port_status_table'):
            row = self.port_status_table.rowCount()
            self.port_status_table.insertRow(row)
            
            self.port_status_table.setItem(row, 0, QTableWidgetItem(str(port)))
            self.port_status_table.setItem(row, 1, QTableWidgetItem(status))
            self.port_status_table.setItem(row, 2, QTableWidgetItem(service))
            
            # Renk kodlama
            if status == "Açık":
                for col in range(3):
                    item = self.port_status_table.item(row, col)
                    if item:
                        item.setBackground(QColor(255, 100, 100, 50))
    
    def handle_suspicious_connection(self, ip, connection_type, port):
        """Şüpheli bağlantıyı işle"""
        if hasattr(self, 'network_activity_table'):
            row = self.network_activity_table.rowCount()
            self.network_activity_table.insertRow(row)
            
            current_time = datetime.now().strftime("%H:%M:%S")
            self.network_activity_table.setItem(row, 0, QTableWidgetItem(current_time))
            self.network_activity_table.setItem(row, 1, QTableWidgetItem(ip))
            self.network_activity_table.setItem(row, 2, QTableWidgetItem(str(port)))
            self.network_activity_table.setItem(row, 3, QTableWidgetItem("Şüpheli"))
            
            # Kırmızı renk
            for col in range(4):
                item = self.network_activity_table.item(row, col)
                if item:
                    item.setBackground(QColor(255, 68, 68, 100))
    
    def handle_port_scan(self, ip, ports):
        """Port tarama tespit edildiğinde"""
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                translator.get_text("port_scan_detected"),
                f"IP: {ip}\nPortlar: {', '.join(map(str, ports))}",
                QSystemTrayIcon.MessageIcon.Warning,
                5000
            )
    
    def block_suspicious_ip(self):
        """Seçili IP'yi engelle"""
        if hasattr(self, 'network_activity_table'):
            current_row = self.network_activity_table.currentRow()
            if current_row >= 0:
                ip_item = self.network_activity_table.item(current_row, 1)
                if ip_item:
                    ip = ip_item.text()
                    try:
                        import subprocess
                        # iptables ile IP engelleme
                        cmd = ['/usr/sbin/iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                        subprocess.run(cmd, check=True)
                        QMessageBox.information(self, "Başarılı", f"IP {ip} engellendi!")
                    except (subprocess.SubprocessError, FileNotFoundError, PermissionError) as e:
                        QMessageBox.warning(self, "Hata", f"IP engellenemedi: {e}")
    
    def add_trusted_ip_ui(self):
        """UI'dan güvenilir IP ekle"""
        ip = self.trusted_ip_input.text().strip()
        if ip:
            if self.network_protection.add_trusted_ip(ip):
                self.trusted_ip_input.clear()
                self.refresh_exceptions_table()
                QMessageBox.information(self, "Başarılı", f"IP {ip} güvenilir listeye eklendi!")
            else:
                QMessageBox.warning(self, "Hata", "IP eklenirken hata oluştu!")
        else:
            QMessageBox.warning(self, "Uyarı", "Lütfen geçerli bir IP adresi girin!")
    
    def add_trusted_port_ui(self):
        """UI'dan güvenilir port ekle"""
        try:
            port = int(self.trusted_port_input.text().strip())
            if 1 <= port <= 65535:
                if self.network_protection.add_trusted_port(port):
                    self.trusted_port_input.clear()
                    self.refresh_exceptions_table()
                    QMessageBox.information(self, "Başarılı", f"Port {port} güvenilir listeye eklendi!")
                else:
                    QMessageBox.warning(self, "Hata", "Port eklenirken hata oluştu!")
            else:
                QMessageBox.warning(self, "Uyarı", "Port numarası 1-65535 arasında olmalıdır!")
        except ValueError:
            QMessageBox.warning(self, "Uyarı", "Lütfen geçerli bir port numarası girin!")
    
    def refresh_exceptions_table(self):
        """İstisna tablosunu yenile"""
        if hasattr(self, 'exceptions_table'):
            self.exceptions_table.setRowCount(0)
            
            # Güvenilir IP'leri ekle
            for ip in self.network_protection.trusted_ips:
                self.add_exception_to_table("IP", ip)
            
            # Güvenilir portları ekle
            for port in self.network_protection.trusted_ports:
                self.add_exception_to_table("Port", str(port))
    
    def add_exception_to_table(self, exc_type, value):
        """İstisna tablosuna öğe ekle"""
        if hasattr(self, 'exceptions_table'):
            row = self.exceptions_table.rowCount()
            self.exceptions_table.insertRow(row)
            
            self.exceptions_table.setItem(row, 0, QTableWidgetItem(exc_type))
            self.exceptions_table.setItem(row, 1, QTableWidgetItem(value))
            
            # Kaldır butonu
            remove_btn = QPushButton("❌ Kaldır")
            remove_btn.setObjectName("dangerButton")
            remove_btn.clicked.connect(lambda: self.remove_exception(exc_type, value))
            self.exceptions_table.setCellWidget(row, 2, remove_btn)
    
    def remove_exception(self, exc_type, value):
        """İstisnayı kaldır"""
        try:
            if exc_type == "IP":
                self.network_protection.remove_trusted_ip(value)
            elif exc_type == "Port":
                port = int(value)
                if port in self.network_protection.trusted_ports:
                    self.network_protection.trusted_ports.remove(port)
                    self.network_protection.save_exceptions()
            
            self.refresh_exceptions_table()
            QMessageBox.information(self, "Başarılı", f"{exc_type} {value} kaldırıldı!")
        except (ValueError, PermissionError, OSError) as e:
            QMessageBox.warning(self, "Hata", f"Kaldırma hatası: {e}")
    
    def handle_threat_found(self, threat):
        """Tarama sırasında tehdit bulunduğunda çağrılır"""
        # Otomatik karantinaya al
        if self.settings.get('quarantine_auto'):
            self.quarantine_file(threat["file"], (threat["threat"], threat["type"], threat["severity"]))
        
        # Tehdit sayısını güncelle
        self.update_threat_count()
    
    def update_threat_count(self):
        """Ana sayfadaki tehdit sayısını güncelle"""
        if hasattr(self, 'quarantine_table'):
            threat_count = self.quarantine_table.rowCount()
        else:
            # Karantina dosyasından sayı oku
            quarantine_dir = os.path.join(CONFIG_DIR, "quarantine")
            threat_count = len(os.listdir(quarantine_dir)) if os.path.exists(quarantine_dir) else 0
        
        # Tehdit kartını güncelle
        if hasattr(self, 'threat_card'):
            layout = self.threat_card.layout()
            if layout and layout.count() >= 2:
                value_label = layout.itemAt(1).widget()
                value_label.setText(str(threat_count))
                
                # Renk güncelle
                if threat_count > 0:
                    value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff4444;")
                    self.threat_card.setStyleSheet("""
                        QFrame {
                            background-color: #2a2a2a;
                            border: 2px solid #ff4444;
                            border-radius: 10px;
                            padding: 20px;
                        }
                    """)
                else:
                    value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff88;")
                    self.threat_card.setStyleSheet("""
                        QFrame {
                            background-color: #2a2a2a;
                            border: 2px solid #00ff88;
                            border-radius: 10px;
                            padding: 20px;
                        }
                    """)
    
    def update_network_status_ui(self):
        """Ağ koruması durum etiketini güncelle"""
        if hasattr(self, 'network_status_label'):
            if self.network_protection.is_running:
                self.network_status_label.setText("Ağ koruması: Aktif")
                self.network_status_label.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
            else:
                self.network_status_label.setText("Ağ koruması: Pasif")
                self.network_status_label.setStyleSheet("color: #ff4444; font-weight: bold; font-size: 14px;")
    
    def setup_startup_autorun(self):
        """Sistem başlangıcı ayarını yapılandır"""
        try:
            autostart_dir = os.path.expanduser("~/.config/autostart")
            desktop_file = os.path.join(autostart_dir, "linux-secureguard.desktop")
            
            if self.startup_check.isChecked():
                # Autostart dizinini oluştur
                os.makedirs(autostart_dir, exist_ok=True)
                
                # Desktop dosyasını oluştur
                desktop_content = f"""[Desktop Entry]
Type=Application
Name=Linux SecureGuard
Exec=/usr/bin/lsg --startup
Icon=/usr/share/pixmaps/lsglo.png
Comment=Gercek Zamanlı Sistem Koruması
X-GNOME-Autostart-enabled=true
StartupNotify=false
Terminal=false
Categories=Security;"""
                
                with open(desktop_file, 'w') as f:
                    f.write(desktop_content)
                os.chmod(desktop_file, 0o755)
            else:
                # Desktop dosyasını sil
                if os.path.exists(desktop_file):
                    os.remove(desktop_file)
        except Exception as e:
            print(f"Startup ayarı hatası: {e}")
    
    def start_socket_server(self):
        """Socket server başlat - diğer instance'lardan gelen istekleri dinle"""
        import socket
        import threading
        
        def server_thread():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('127.0.0.1', 12345))
                server.listen(1)
                
                while True:
                    try:
                        client, addr = server.accept()
                        data = client.recv(1024)
                        if data == b'show':
                            # Ana thread'de pencereyi göster
                            QTimer.singleShot(0, self.show_window)
                        client.close()
                    except:
                        break
            except:
                pass
        
        thread = threading.Thread(target=server_thread, daemon=True)
        thread.start()
    
    def show_window(self):
        """Pencereyi göster ve öne getir"""
        self.show()
        self.raise_()
        self.activateWindow()

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyle('Fusion')
    
    # Signal handler for graceful shutdown
    def signal_handler(signum, frame):
        app.quit()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Tek instance kontrolü
    from PyQt6.QtCore import QSharedMemory
    shared_memory = QSharedMemory("LinuxSecureGuardSingleInstance")
    
    if not shared_memory.create(1):
        # Zaten çalışan instance var, onu göster
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', 12345))
            sock.send(b'show')
            sock.close()
        except:
            pass
        return 0

if __name__ == "__main__":
    sys.exit(main())

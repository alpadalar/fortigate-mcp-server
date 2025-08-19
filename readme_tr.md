# FortiGate MCP Server

FortiGate cihazlarını yönetmek için Model Context Protocol (MCP) sunucusu. Bu proje, FortiGate cihazlarına programatik erişim sağlar ve Cursor gibi MCP destekli araçlarla entegrasyon imkanı sunar.

## 🚀 Özellikler

- **Cihaz Yönetimi**: FortiGate cihazlarını ekleme, kaldırma ve bağlantı testi
- **Firewall Yönetimi**: Firewall kurallarını listeleme, oluşturma, güncelleme ve silme
- **Ağ Yönetimi**: Adres ve servis nesnelerini yönetme
- **Routing Yönetimi**: Statik rotaları ve arayüzleri yönetme
- **HTTP Transport**: FastMCP ile HTTP üzerinden MCP protokolü
- **Docker Desteği**: Kolay kurulum ve dağıtım
- **Cursor Entegrasyonu**: Cursor IDE ile tam entegrasyon

## 📋 Gereksinimler

- Python 3.8+
- FortiGate cihazına erişim
- API token veya kullanıcı adı/şifre

## 🛠️ Kurulum

### 1. Projeyi Klonlayın

```bash
git clone <repository-url>
cd fortigate-mcp-server
```

### 2. Bağımlılıkları Yükleyin

```bash
# Virtual environment oluşturun
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# veya
.venv\Scripts\activate  # Windows

# Bağımlılıkları yükleyin
pip install -r requirements.txt
```

### 3. Konfigürasyon

`config/config.json` dosyasını düzenleyin:

```json
{
  "fortigate": {
    "devices": {
      "default": {
        "host": "192.168.1.1",
        "port": 443,
        "username": "admin",
        "password": "password",
        "api_token": "your-api-token",
        "vdom": "root",
        "verify_ssl": false,
        "timeout": 30
      }
    }
  },
  "logging": {
    "level": "INFO",
    "file": "./logs/fortigate_mcp.log"
  }
}
```

## 🚀 Kullanım

### HTTP Server Başlatma

```bash
# Script ile başlat
./start_http_server.sh

# Veya manuel olarak
python -m src.fortigate_mcp.server_http \
  --host 0.0.0.0 \
  --port 8814 \
  --path /fortigate-mcp \
  --config config/config.json
```

### Docker ile Çalıştırma

```bash
# Build ve başlat
docker-compose up -d

# Logları görüntüle
docker-compose logs -f fortigate-mcp-server
```

## 🔧 Cursor MCP Entegrasyonu

### 1. Cursor MCP Konfigürasyonu

Cursor'da `~/.cursor/mcp_servers.json` dosyasını düzenleyin:

#### Seçenek 1: Command ile Bağlantı

```json
{
  "mcpServers": {
    "fortigate-mcp": {
      "command": "python",
      "args": [
        "-m",
        "src.fortigate_mcp.server_http",
        "--host",
        "0.0.0.0",
        "--port",
        "8814",
        "--path",
        "/fortigate-mcp",
        "--config",
        "/path/to/your/config.json"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/path/to/your/config.json"
      }
    }
  }
}
```

#### Seçenek 2: URL ile Bağlantı (Önerilen)

```json
{
  "mcpServers": {
    "FortiGateMCP": {
      "url": "http://0.0.0.0:8814/fortigate-mcp/",
      "transport": "http"
    }
  }
}
```

### 2. Cursor'da Kullanım

Cursor'da FortiGate MCP'yi kullanmak için:

1. **Server'ı başlatın:**
```bash
cd /media/workspace/fortigate-mcp-server
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --path /fortigate-mcp --config config/config.json
```

2. **Cursor'u yeniden başlatın**
3. **MCP server'ın başladığından emin olun**
4. **Cursor'da FortiGate komutlarını kullanın**

## 📚 API Komutları

### Cihaz Yönetimi

- `list_devices` - Kayıtlı cihazları listele
- `get_device_status` - Cihaz durumunu al
- `test_device_connection` - Bağlantıyı test et
- `add_device` - Yeni cihaz ekle
- `remove_device` - Cihaz kaldır
- `discover_vdoms` - VDOM'ları keşfet

### Firewall Yönetimi

- `list_firewall_policies` - Firewall kurallarını listele
- `create_firewall_policy` - Yeni kural oluştur
- `update_firewall_policy` - Kural güncelle
- `delete_firewall_policy` - Kural sil

### Ağ Yönetimi

- `list_address_objects` - Adres nesnelerini listele
- `create_address_object` - Adres nesnesi oluştur
- `list_service_objects` - Servis nesnelerini listele
- `create_service_object` - Servis nesnesi oluştur

### Virtual IP Yönetimi

- `list_virtual_ips` - Virtual IP'leri listele
- `create_virtual_ip` - Virtual IP oluştur
- `update_virtual_ip` - Virtual IP güncelle
- `get_virtual_ip_detail` - Virtual IP detayını al
- `delete_virtual_ip` - Virtual IP sil

### Routing Yönetimi

- `list_static_routes` - Statik rotaları listele
- `create_static_route` - Statik rota oluştur
- `update_static_route` - Statik rota güncelle
- `delete_static_route` - Statik rota sil
- `get_static_route_detail` - Statik rota detayını al
- `get_routing_table` - Routing tablosunu al
- `list_interfaces` - Arayüzleri listele
- `get_interface_status` - Arayüz durumunu al

### Sistem Komutları

- `health` - Sağlık kontrolü
- `test_connection` - Bağlantı testi
- `get_schema_info` - Schema bilgisi

## 🧪 Test

### Test Çalıştırma

```bash
# Tüm unit testleri çalıştır (varsayılan)
python -m pytest

# Coverage ile çalıştır
python -m pytest --cov=src --cov-report=html

# Belirli test kategorilerini çalıştır
python -m pytest tests/test_device_manager.py
python -m pytest tests/test_fortigate_api.py
python -m pytest tests/test_tools.py

# Integration testlerini çalıştır (server çalışması gerekir)
python integration_tests.py

# Sadece unit testleri çalıştır (varsayılan)
python -m pytest tests/

# Detaylı çıktı ile çalıştır
python -m pytest -v

# Detaylı hata bilgisi ile çalıştır
python -m pytest --tb=long
```

### Test Kategorileri

- **Unit Testler**: Bireysel bileşenleri ve fonksiyonları test eder
- **Integration Testler**: HTTP server işlevselliğini test eder (server çalışması gerekir)
- **Coverage**: HTML çıktısı ile kod coverage raporlaması

### HTTP Server Test

```bash
# Test script'ini çalıştır
python test_http_server.py
```

### Manuel Test

```bash
# Health check
curl -X POST http://localhost:8814/fortigate-mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "health", "params": {}}'

# List devices
curl -X POST http://localhost:8814/fortigate-mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "list_devices", "params": {}}'
```

## 📁 Proje Yapısı

```
fortigate-mcp-server/
├── src/
│   └── fortigate_mcp/
│       ├── __init__.py
│       ├── server_http.py          # HTTP MCP server
│       ├── config/                 # Konfigürasyon yönetimi
│       ├── core/                   # Temel bileşenler
│       ├── tools/                  # MCP araçları
│       └── formatting/             # Response formatting
├── config/
│   ├── config.json                # Ana konfigürasyon
│   └── config.example.json        # Örnek konfigürasyon
├── examples/
│   └── cursor_mcp_config.json     # Cursor MCP config
├── logs/                          # Log dosyaları
├── tests/                         # Test dosyaları
├── docker-compose.yml             # Docker compose
├── Dockerfile                     # Docker image
├── start_http_server.sh           # Başlatma script'i
├── test_http_server.py            # Test script'i
└── README.md                      # Bu dosya
```

## 🔍 Sorun Giderme

### Yaygın Sorunlar

1. **Bağlantı Hatası**
   - FortiGate cihazının erişilebilir olduğundan emin olun
   - API token veya kullanıcı adı/şifre doğru olmalı
   - SSL sertifikası sorunları için `verify_ssl: false` kullanın

2. **Port Çakışması**
   - 8814 portunun kullanılabilir olduğundan emin olun
   - Farklı port kullanmak için `--port` parametresini değiştirin

3. **Konfigürasyon Hatası**
   - `config.json` dosyasının doğru formatta olduğundan emin olun
   - JSON syntax'ını kontrol edin

4. **Cursor MCP Bağlantı Sorunu**
   - Server'ın çalıştığından emin olun
   - URL'nin doğru olduğunu kontrol edin
   - Cursor'u yeniden başlatın

### Loglar

Logları kontrol etmek için:

```bash
# HTTP server logları
tail -f logs/fortigate_mcp.log

# Docker logları
docker-compose logs -f fortigate-mcp-server
```

## 🔒 Güvenlik

### Öneriler

1. **API Token Kullanın**
   - Kullanıcı adı/şifre yerine API token kullanın
   - Token'ları güvenli şekilde saklayın

2. **SSL Sertifikası**
   - Üretim ortamında SSL sertifikası kullanın
   - `verify_ssl: true` yapın

3. **Ağ Güvenliği**
   - MCP server'ı sadece güvenli ağlarda çalıştırın
   - Firewall kuralları ile erişimi kısıtlayın

4. **Rate Limiting**
   - Rate limiting'i etkinleştirin
   - API çağrılarını sınırlayın

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull request gönderin

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 🙏 Teşekkürler

- [FastMCP](https://gofastmcp.com/) - MCP HTTP transport için
- [FortiGate API](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/109229/rest-api) - FortiGate entegrasyonu için
- [Cursor](https://cursor.sh/) - MCP desteği için

## 📞 Destek

Sorunlarınız için:
- [Issues](https://github.com/your-repo/issues) sayfasını kullanın
- Dokümantasyonu kontrol edin
- Logları inceleyin

---

**Not**: Bu proje FortiGate cihazlarıyla test edilmiştir. Üretim ortamında kullanmadan önce kapsamlı test yapın.

# FortiGate MCP HTTP Server Guide

Bu rehber, FortiGate MCP HTTP Server'ının nasıl kurulacağını ve kullanılacağını açıklar.

## Kurulum

### 1. Gereksinimler

- Python 3.8+
- pip veya uv
- FortiGate cihazına erişim

### 2. Bağımlılıkları Yükleme

```bash
# Virtual environment oluştur
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# veya
.venv\Scripts\activate  # Windows

# Bağımlılıkları yükle
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

## Kullanım

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

## Cursor MCP Entegrasyonu

### 1. Cursor MCP Konfigürasyonu

Cursor'da `~/.cursor/mcp_servers.json` dosyasını düzenleyin:

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

### 2. Cursor'da Kullanım

Cursor'da FortiGate MCP'yi kullanmak için:

1. Cursor'u yeniden başlatın
2. MCP server'ın başladığından emin olun
3. Cursor'da FortiGate komutlarını kullanın

## API Endpoints

### Temel Endpoints

- `GET /fortigate-mcp/health` - Sağlık kontrolü
- `POST /fortigate-mcp` - MCP komutları

### MCP Komutları

#### Cihaz Yönetimi
- `list_devices` - Kayıtlı cihazları listele
- `get_device_status` - Cihaz durumunu al
- `test_device_connection` - Bağlantıyı test et
- `add_device` - Yeni cihaz ekle
- `remove_device` - Cihaz kaldır

#### Firewall Yönetimi
- `list_firewall_policies` - Firewall kurallarını listele
- `create_firewall_policy` - Yeni kural oluştur
- `update_firewall_policy` - Kural güncelle
- `delete_firewall_policy` - Kural sil

#### Ağ Yönetimi
- `list_address_objects` - Adres nesnelerini listele
- `create_address_object` - Adres nesnesi oluştur
- `list_service_objects` - Servis nesnelerini listele
- `create_service_object` - Servis nesnesi oluştur

#### Routing Yönetimi
- `list_static_routes` - Statik rotaları listele
- `create_static_route` - Statik rota oluştur
- `list_interfaces` - Arayüzleri listele
- `get_interface_status` - Arayüz durumunu al

## Test

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
  -d '{"jsonrpc": "2.0", "id": 1, "method": "health", "params": {}}'

# List devices
curl -X POST http://localhost:8814/fortigate-mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "list_devices", "params": {}}'
```

## Sorun Giderme

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

### Loglar

Logları kontrol etmek için:

```bash
# HTTP server logları
tail -f logs/fortigate_mcp.log

# Docker logları
docker-compose logs -f fortigate-mcp-server
```

## Güvenlik

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

## Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Pull request gönderin

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

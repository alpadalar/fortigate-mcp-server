# FortiGate MCP HTTP Server Guide

Bu rehber, FortiGate MCP HTTP Server'ının nasıl kurulacağını ve kullanılacağını açıklar.

## Kurulum

### 1. Gereksinimler

- Python 3.11+
- `uv` (önerilen) veya pip
- FortiGate cihazına erişim

### 2. Bağımlılıkları Yükleme

```bash
# uv ile (önerilen) -- kilitli, tekrarlanabilir bağımlılık kümesini kurar
uv sync --locked

# Veya pip ile
pip install -e .
```

### 3. Konfigürasyon

Örnek dosyadan kendi yerel konfigürasyonunuzu oluşturun (`config/config.json` git tarafından
takip edilmez ve temiz bir klonda mevcut değildir):

```bash
cp config/config.example.json config/config.json
```

Ardından `config/config.json` dosyasını düzenleyin:

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
        "verify_ssl": true,
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
  --host 127.0.0.1 \
  --port 8814 \
  --path /fortigate-mcp \
  --config config/config.json
```

`--host` için `0.0.0.0` değerini yalnızca ağdaki başka makinelerden erişim gerekiyorsa VE
`config/config.json` içinde `auth.require_auth=true` etkinse kullanın; aksi halde `127.0.0.1`
değerinde kalın — kimlik doğrulamasız HTTP asla loopback'ten daha geniş bir adrese
bağlanmamalıdır. (`./start_http_server.sh` de varsayılan olarak `127.0.0.1` adresine bağlanır;
daha geniş bir bind için `MCP_HTTP_HOST` ortam değişkenini bilinçli olarak ayarlamanız gerekir.)

### Docker ile Çalıştırma

```bash
# Build ve başlat
docker-compose up -d

# Logları görüntüle
docker-compose logs -f fortigate-mcp-server
```

Compose dosyası 8814 portunu yalnızca loopback üzerinde (`127.0.0.1:8814:8814`) yayınlar; sunucuya
sadece Docker host'un kendisinden erişilebilir. Portu `127.0.0.1` dışına açmadan önce
`config/config.json` içinde `auth.require_auth=true` ayarlayın ve `ports:` eşlemesini bilinçli
olarak genişletin — bkz. SECURITY.md.

## MCP İstemci Entegrasyonu

FortiGate MCP Server, herhangi bir MCP uyumlu istemciyle çalışır. Claude Desktop, Claude Code ve
Cursor için doğrulanmış konfigürasyon örnekleri `examples/` dizini altında bulunur:

- `examples/claude_desktop_config.stdio.json` — Claude Desktop, stdio transport (önerilen)
- `examples/claude_desktop_config.http.json` — Claude Desktop, `mcp-remote` köprüsü üzerinden HTTP transport
- `examples/claude_code_mcp.json` — Claude Code proje-kapsamlı `.mcp.json` (stdio + HTTP)
- `examples/cursor_mcp_config.json` — Cursor MCP konfigürasyonu

Her stdio örneği, `python -m ...` yerine `uv run --directory <yol> python -m
src.fortigate_mcp.server` çağrısını kullanır -- Claude Desktop gibi GUI tabanlı istemciler komutu
genellikle repo kökü dışındaki bir dizinden başlattığı için `--directory` bayrağı bu çağrıyı
çalışma dizininden bağımsız kılar. Bu proje README.md'nin "MCP Client Integration" bölümünde aynı
örnekleri İngilizce olarak da açıklar; bu bölüm o anlatımı tekrar etmek yerine örnek dosyalara
işaret eder.

Yetkisiz (kimlik doğrulamasız) HTTP sunucusu için `127.0.0.1` (loopback) adresine bağlanmanız
önerilir; `auth.require_auth=true` etkinleştirilmeden `0.0.0.0` gibi daha geniş bir adrese
bağlanmayın.

### Cursor'da Kullanım

Cursor'da FortiGate MCP'yi kullanmak için:

1. Cursor'u yeniden başlatın
2. MCP server'ın başladığından emin olun
3. Cursor'da FortiGate komutlarını kullanın

## API Endpoints

### Temel Endpoints

- `GET /health` - Sağlık kontrolü (uygulama kökünde; `/fortigate-mcp` altında değil)
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

### Manuel Test

`/health` ucu uygulama kökünde bulunur, Bearer-token doğrulamasından muaftır ve düz `curl`
ile çalışır:

```bash
# Canlılık kontrolü (liveness probe)
curl http://127.0.0.1:8814/health
```

MCP protokolünün kendisi düz bir `curl` POST ile test edilemez: streamable-HTTP taşıyıcısı
`initialize` el sıkışması, oturum yönetimi ve `tools/call` çerçevelemesi gerektirir. Protokol
seviyesinde test için gerçek bir MCP istemcisi kullanın — örneğin `fastmcp.Client`:

```bash
uv run python - <<'PY'
import asyncio
from fastmcp import Client

async def main():
    # Sondaki '/' mount kuralıyla eşleşir; eğik çizgisiz form 307 ile yönlendirilir
    async with Client("http://127.0.0.1:8814/fortigate-mcp/") as client:
        tools = await client.list_tools()
        print(f"{len(tools)} tool kayıtlı")
        result = await client.call_tool("health", {})
        print(result.content[0].text)

asyncio.run(main())
PY
```

Alternatif olarak `npx -y mcp-remote http://127.0.0.1:8814/fortigate-mcp` köprüsü veya MCP
Inspector da kullanılabilir.

## Sorun Giderme

### Yaygın Sorunlar

1. **Bağlantı Hatası**
   - FortiGate cihazının erişilebilir olduğundan emin olun
   - API token veya kullanıcı adı/şifre doğru olmalı
   - SSL sertifikası hatası alıyorsanız, FortiGate cihazının sertifikasını güvenilir olarak
     yükleyin (veya CA imzalı bir sertifika ile değiştirin) -- sertifika doğrulamasını asla
     devre dışı bırakmayın. `verify_ssl` varsayılan olarak `true` değerini alır ve bu şekilde
     kalmalıdır; ayrıntılar için SECURITY.md dosyasına bakın.

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
   - `verify_ssl: true` yapın (varsayılan değerdir, değiştirmeyin)

3. **Ağ Güvenliği**
   - MCP server'ı sadece güvenli ağlarda çalıştırın
   - Yetkisiz (kimlik doğrulamasız) HTTP için `127.0.0.1` (loopback) adresine bağlanın;
     `0.0.0.0` gibi daha geniş bir adrese bağlanmak `auth.require_auth=true` gerektirir
   - Firewall kuralları ile erişimi kısıtlayın

4. **Rate Limiting**
   - Rate limiting şu anda parse edilir ama uygulanmaz (enforce edilmez) -- çalışan bir kontrol
     olarak güvenmeyin

## Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Pull request gönderin

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

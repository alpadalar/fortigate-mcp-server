#!/usr/bin/env python3
"""
FortiGate MCP Server

FastMCP kullanarak FortiGate cihazlarını yönetmek için MCP sunucusu.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict, Any
import yaml

from fastmcp import FastMCP
from .tools import (
    register_device_management_tools,
    register_firewall_policy_tools,
    register_network_objects_tools,
    register_routing_management_tools,
    device_manager
)


# Logging konfigürasyonu
def setup_logging(log_level: str = "INFO") -> None:
    """Logging konfigürasyonunu ayarlar"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('fortigate_mcp.log')
        ]
    )


def load_configuration() -> Dict[str, Any]:
    """Konfigürasyon dosyasını yükler"""
    # Config dosyasının yolunu belirle
    config_path = Path(__file__).parent.parent / "config" / "config.yaml"
    
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            if config is None:
                config = {}
    except FileNotFoundError:
        logging.error(f"Config file not found: {config_path}")
        logging.error("Please create config/config.yaml file based on config/config.example.yaml")
        raise FileNotFoundError(f"Configuration file required: {config_path}")
    except yaml.YAMLError as e:
        logging.error(f"Error parsing config file: {e}")
        raise yaml.YAMLError(f"Invalid YAML configuration: {e}")
    
    # Varsayılan değerleri ayarla
    if 'server' not in config:
        config['server'] = {}
    
    server_config = config['server']
    server_config.setdefault('host', '0.0.0.0')
    server_config.setdefault('port', 8814)
    server_config.setdefault('name', 'fortigate-mcp-server')
    server_config.setdefault('version', '1.0.0')
    
    if 'logging' not in config:
        config['logging'] = {}
    
    logging_config = config['logging']
    logging_config.setdefault('level', 'INFO')
    logging_config.setdefault('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    if 'rate_limiting' not in config:
        config['rate_limiting'] = {}
        
    rate_limit_config = config['rate_limiting']
    rate_limit_config.setdefault('enabled', True)
    rate_limit_config.setdefault('max_requests_per_minute', 60)
    
    return config


async def initialize_default_devices(config: Dict[str, Any]) -> None:
    """Varsayılan cihazları device manager'a ekler"""
    devices_config = config.get('fortigate_devices', {})
    
    for device_id, device_config in devices_config.items():
        try:
            result = device_manager.add_device(
                device_id=device_id,
                host=device_config['host'],
                username=device_config.get('username'),
                password=device_config.get('password'),
                api_token=device_config.get('api_token'),
                vdom=device_config.get('vdom', 'root'),
                verify_ssl=device_config.get('verify_ssl', False),
                timeout=device_config.get('timeout', 30),
                port=device_config.get('port', 443)
            )
            
            if result['success']:
                logging.info(f"Default device '{device_id}' added successfully")
            else:
                logging.error(f"Failed to add default device '{device_id}': {result['message']}")
                
        except Exception as e:
            logging.error(f"Error adding default device '{device_id}': {e}")


def create_mcp_server(config: Dict[str, Any]) -> FastMCP:
    """MCP sunucusunu oluşturur ve araçları kaydeder"""
    server_config = config.get('server', {})
    
    # FastMCP sunucusunu oluştur
    mcp = FastMCP(
        name=server_config.get('name', 'fortigate-mcp-server'),
        version=server_config.get('version', '1.0.0')
    )
    
    # Araçları kaydet
    register_device_management_tools(mcp)
    register_firewall_policy_tools(mcp)
    register_network_objects_tools(mcp)
    register_routing_management_tools(mcp)
    
    # Health check endpoint'i ekle
    @mcp.tool()
    async def health_check() -> Dict[str, Any]:
        """Sunucu sağlık kontrolü"""
        try:
            device_count = len(device_manager.devices)
            return {
                "status": "healthy",
                "timestamp": str(asyncio.get_event_loop().time()),
                "registered_devices": device_count,
                "server_version": server_config.get('version', '1.0.0')
            }
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    # Server bilgilerini al
    @mcp.tool()
    async def get_server_info() -> Dict[str, Any]:
        """Sunucu bilgilerini getirir"""
        try:
            return {
                "name": server_config.get('name', 'fortigate-mcp-server'),
                "version": server_config.get('version', '1.0.0'),
                "host": server_config.get('host', '0.0.0.0'),
                "port": server_config.get('port', 8814),
                "registered_devices": len(device_manager.devices),
                "available_tools": [
                    "Device Management (8 tools)",
                    "Firewall Policy Management (5 tools)",
                    "Network Objects Management (8 tools)",
                    "Routing Management (5 tools)",
                    "Health & Info (2 tools)"
                ]
            }
        except Exception as e:
            logging.error(f"Error getting server info: {e}")
            return {"error": str(e)}
    
    return mcp


def main():
    """Ana fonksiyon"""
    try:
        # Konfigürasyonu yükle
        config = load_configuration()
        
        # Logging'i ayarla
        log_level = config.get('logging', {}).get('level', 'INFO')
        setup_logging(log_level)
        
        logger = logging.getLogger(__name__)
        logger.info("FortiGate MCP Server starting...")
        
        # MCP sunucusunu oluştur
        mcp = create_mcp_server(config)
        
        # Varsayılan cihazları ekle (sync olarak)
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(initialize_default_devices(config))
        loop.close()
        
        # Sunucu konfigürasyonunu logla
        server_config = config.get('server', {})
        host = server_config.get('host', '0.0.0.0')
        port = server_config.get('port', 8814)
        
        logger.info(f"Starting MCP server on {host}:{port}")
        logger.info(f"Registered devices: {len(device_manager.devices)}")
        
        # Sunucuyu başlat - FastMCP HTTP sunucu modu için uvicorn kullan
        import uvicorn
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware
        
        app = FastAPI(title="FortiGate MCP Server")
        
        # CORS ayarları
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # MCP endpoint'lerini ekle
        @app.post("/fortigate-mcp")
        async def handle_mcp(request: dict):
            """MCP isteklerini işler"""
            # MCP protocol handler buraya gelecek
            return {"status": "ok", "message": "FortiGate MCP Server is running"}
        
        @app.get("/")
        async def root():
            return {"message": "FortiGate MCP Server", "version": "1.0.0"}
        
        @app.get("/health")
        async def health():
            return {
                "status": "healthy",
                "registered_devices": len(device_manager.devices),
                "server_version": "1.0.0"
            }
        
        # HTTP sunucuyu başlat
        uvicorn.run(app, host=host, port=port, log_level="info")
        
    except KeyboardInterrupt:
        logging.info("Server shutdown requested")
    except Exception as e:
        logging.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Direkt main() çağır, FastMCP kendi event loop'unu yönetsin
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

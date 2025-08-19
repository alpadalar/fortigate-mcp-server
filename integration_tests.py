#!/usr/bin/env python3
"""
Integration tests for FortiGate MCP HTTP Server

This script tests the HTTP server functionality by making requests
to the MCP endpoints and verifying responses.
"""

import requests
import json
import time
import sys
from typing import Dict, Any

# Server configuration
SERVER_URL = "http://localhost:8814"
MCP_PATH = "/fortigate-mcp"

def make_mcp_request(method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """Make a request to the MCP server."""
    url = f"{SERVER_URL}{MCP_PATH}"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
    
    data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {}
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return {"error": str(e)}

def test_server_health():
    """Test server health endpoint."""
    print("🔍 Testing server health...")
    
    try:
        response = requests.get(f"{SERVER_URL}/health", timeout=10)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Server health: {health_data.get('status', 'unknown')}")
            print(f"   Registered devices: {health_data.get('registered_devices', 0)}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_mcp_initialize():
    """Test MCP initialization."""
    print("🔍 Testing MCP initialization...")
    
    params = {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "clientInfo": {
            "name": "integration-test",
            "version": "1.0.0"
        }
    }
    
    result = make_mcp_request("initialize", params)
    
    if "result" in result:
        print("✅ MCP initialization successful")
        return True
    else:
        print(f"❌ MCP initialization failed: {result}")
        return False

def test_list_tools():
    """Test listing available tools."""
    print("🔍 Testing tool listing...")
    
    result = make_mcp_request("tools/list")
    
    if "result" in result and "tools" in result["result"]:
        tools = result["result"]["tools"]
        print(f"✅ Found {len(tools)} tools:")
        for tool in tools[:5]:  # Show first 5 tools
            print(f"   - {tool.get('name', 'unknown')}")
        if len(tools) > 5:
            print(f"   ... and {len(tools) - 5} more")
        return True
    else:
        print(f"❌ Tool listing failed: {result}")
        return False

def test_list_devices():
    """Test listing devices."""
    print("🔍 Testing device listing...")
    
    result = make_mcp_request("tools/call", {
        "name": "list_devices",
        "arguments": {}
    })
    
    if "result" in result:
        print("✅ Device listing successful")
        return True
    else:
        print(f"❌ Device listing failed: {result}")
        return False

def test_get_device_status():
    """Test getting device status."""
    print("🔍 Testing device status...")
    
    result = make_mcp_request("tools/call", {
        "name": "get_device_status",
        "arguments": {
            "device_id": "default"
        }
    })
    
    if "result" in result:
        print("✅ Device status successful")
        return True
    else:
        print(f"❌ Device status failed: {result}")
        return False

def test_list_firewall_policies():
    """Test listing firewall policies."""
    print("🔍 Testing firewall policies listing...")
    
    result = make_mcp_request("tools/call", {
        "name": "list_firewall_policies",
        "arguments": {
            "device_id": "default"
        }
    })
    
    if "result" in result:
        print("✅ Firewall policies listing successful")
        return True
    else:
        print(f"❌ Firewall policies listing failed: {result}")
        return False

def test_get_policy_detail():
    """Test getting policy detail."""
    print("🔍 Testing policy detail...")
    
    result = make_mcp_request("tools/call", {
        "name": "get_firewall_policy_detail",
        "arguments": {
            "device_id": "default",
            "policy_id": "35"
        }
    })
    
    if "result" in result:
        print("✅ Policy detail successful")
        return True
    else:
        print(f"❌ Policy detail failed: {result}")
        return False

def test_list_address_objects():
    """Test listing address objects."""
    print("🔍 Testing address objects listing...")
    
    result = make_mcp_request("tools/call", {
        "name": "list_address_objects",
        "arguments": {
            "device_id": "default"
        }
    })
    
    if "result" in result:
        print("✅ Address objects listing successful")
        return True
    else:
        print(f"❌ Address objects listing failed: {result}")
        return False

def test_list_service_objects():
    """Test listing service objects."""
    print("🔍 Testing service objects listing...")
    
    result = make_mcp_request("tools/call", {
        "name": "list_service_objects",
        "arguments": {
            "device_id": "default"
        }
    })
    
    if "result" in result:
        print("✅ Service objects listing successful")
        return True
    else:
        print(f"❌ Service objects listing failed: {result}")
        return False

def test_list_static_routes():
    """Test listing static routes."""
    print("🔍 Testing static routes listing...")
    
    result = make_mcp_request("tools/call", {
        "name": "list_static_routes",
        "arguments": {
            "device_id": "default"
        }
    })
    
    if "result" in result:
        print("✅ Static routes listing successful")
        return True
    else:
        print(f"❌ Static routes listing failed: {result}")
        return False

def test_list_interfaces():
    """Test listing interfaces."""
    print("🔍 Testing interfaces listing...")
    
    result = make_mcp_request("tools/call", {
        "name": "list_interfaces",
        "arguments": {
            "device_id": "default"
        }
    })
    
    if "result" in result:
        print("✅ Interfaces listing successful")
        return True
    else:
        print(f"❌ Interfaces listing failed: {result}")
        return False

def run_all_tests():
    """Run all integration tests."""
    print("🚀 Starting FortiGate MCP Integration Tests")
    print("=" * 50)
    
    tests = [
        ("Server Health", test_server_health),
        ("MCP Initialize", test_mcp_initialize),
        ("List Tools", test_list_tools),
        ("List Devices", test_list_devices),
        ("Device Status", test_get_device_status),
        ("Firewall Policies", test_list_firewall_policies),
        ("Policy Detail", test_get_policy_detail),
        ("Address Objects", test_list_address_objects),
        ("Service Objects", test_list_service_objects),
        ("Static Routes", test_list_static_routes),
        ("Interfaces", test_list_interfaces),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            failed += 1
        
        time.sleep(1)  # Small delay between tests
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results:")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   📈 Success Rate: {passed/(passed+failed)*100:.1f}%")
    
    if failed == 0:
        print("🎉 All tests passed!")
        return True
    else:
        print("⚠️ Some tests failed!")
        return False

if __name__ == "__main__":
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏹️ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)

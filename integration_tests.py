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

def test_health_check():
    """Test health check endpoint."""
    print("Testing health check...")
    
    result = make_mcp_request("health")
    print(f"Health check result: {json.dumps(result, indent=2)}")
    
    if "error" not in result:
        print("✅ Health check passed")
        return True
    else:
        print("❌ Health check failed")
        return False

def test_list_devices():
    """Test list devices endpoint."""
    print("\nTesting list devices...")
    
    result = make_mcp_request("list_devices")
    print(f"List devices result: {json.dumps(result, indent=2)}")
    
    if "error" not in result:
        print("✅ List devices passed")
        return True
    else:
        print("❌ List devices failed")
        return False

def test_schema_info():
    """Test schema info endpoint."""
    print("\nTesting schema info...")
    
    result = make_mcp_request("get_schema_info")
    print(f"Schema info result: {json.dumps(result, indent=2)}")
    
    if "error" not in result:
        print("✅ Schema info passed")
        return True
    else:
        print("❌ Schema info failed")
        return False

def test_connection():
    """Test connection endpoint."""
    print("\nTesting connection...")
    
    result = make_mcp_request("test_connection")
    print(f"Connection test result: {json.dumps(result, indent=2)}")
    
    if "error" not in result:
        print("✅ Connection test passed")
        return True
    else:
        print("❌ Connection test failed")
        return False

def main():
    """Run all integration tests."""
    print("FortiGate MCP HTTP Server Integration Tests")
    print("=" * 50)
    
    # Wait for server to start
    print("Waiting for server to start...")
    time.sleep(2)
    
    tests = [
        test_health_check,
        test_list_devices,
        test_schema_info,
        test_connection
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Integration Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        sys.exit(0)
    else:
        print("❌ Some integration tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()

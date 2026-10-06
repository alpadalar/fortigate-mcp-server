"""
Formatting and templates tests
"""


from src.fortigate_mcp.formatting.templates import FortiGateTemplates
from src.fortigate_mcp.formatting.formatters import FortiGateFormatters
from mcp.types import TextContent


class TestFortiGateTemplates:
    """FortiGate Templates test class"""
    
    def test_firewall_policies_empty(self):
        """Empty firewall policies template test"""
        data = {"results": []}
        result = FortiGateTemplates.firewall_policies(data)
        
        assert "Firewall Policies" in result
        assert "No firewall policies found" in result
    
    def test_firewall_policies_with_data(self):
        """Firewall policies template test with data"""
        data = {
            "results": [
                {
                    "policyid": 1,
                    "name": "Test_Policy",
                    "srcintf": [{"name": "port1"}],
                    "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}],
                    "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}],
                    "action": "accept",
                    "status": "enable"
                }
            ]
        }
        result = FortiGateTemplates.firewall_policies(data)
        
        assert "Firewall Policies" in result
        assert "Test_Policy" in result
        assert "1" in result
        assert "accept" in result
    
    def test_firewall_policy_detail_success(self):
        """Firewall policy detail template test"""
        policy_data = {
            "results": {
                "policyid": 35,
                "name": "WAN->ManDown-Project",
                "srcintf": [{"name": "wan1"}],
                "dstintf": [{"name": "internal"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "Yartu-1-TCP"}, {"name": "Yartu-1-UDP"}],
                "service": [{"name": "ALL"}],
                "action": "accept",
                "status": "enable",
                "uuid": "test-uuid"
            }
        }
        
        address_objects = {
            "results": [
                {"name": "all", "subnet": "0.0.0.0 0.0.0.0"},
                {"name": "Yartu-1-TCP", "subnet": "192.168.1.10 255.255.255.255"}
            ]
        }
        
        service_objects = {
            "results": [
                {"name": "ALL", "protocol": "TCP/UDP/SCTP"}
            ]
        }
        
        result = FortiGateTemplates.firewall_policy_detail(
            policy_data, "test_device", address_objects, service_objects
        )
        
        assert "Policy Detail" in result
        assert "35" in result
        assert "WAN->ManDown-Project" in result
        assert "test_device" in result
    
    def test_firewall_policy_detail_renders_string_schedule_whole(self):
        """cmdb policy responses carry `schedule` as a plain string
        (e.g. "always"); the template must render the whole value, not
        its first character."""
        policy_data = {
            "results": {
                "policyid": 1,
                "name": "test-policy",
                "schedule": "always",
                "action": "accept",
            }
        }

        result = FortiGateTemplates.firewall_policy_detail(policy_data, "test_device")

        assert "Schedule: always" in result
        assert "Schedule: a\n" not in result

    def test_firewall_policy_detail_renders_list_schedule_name(self):
        """A list-shaped schedule (member objects) must render the member
        name."""
        policy_data = {
            "results": {
                "policyid": 2,
                "name": "test-policy",
                "schedule": [{"name": "workhours"}],
                "action": "accept",
            }
        }

        result = FortiGateTemplates.firewall_policy_detail(policy_data, "test_device")

        assert "Schedule: workhours" in result

    def test_firewall_policy_detail_renders_utm_profile_names_and_status(self):
        """VIS-02: UTM profile bindings render by NAME, utm-status renders
        prominently, and logtraffic="utm" no longer collapses to "No"."""
        policy_data = {
            "results": {
                "policyid": 35,
                "name": "test-policy",
                "action": "accept",
                "status": "enable",
                "utm-status": "enable",
                "av-profile": "default",
                "ips-sensor": "protect_high_availability",
                "webfilter-profile": "monitor-all",
                "application-list": "block-social",
                "ssl-ssh-profile": "certificate-inspection",
                "logtraffic": "utm",
            }
        }

        result = FortiGateTemplates.firewall_policy_detail(policy_data, "test_device")

        assert "Antivirus: default" in result
        assert "IPS: protect_high_availability" in result
        assert "Web Filter: monitor-all" in result
        assert "Application Control: block-social" in result
        assert "SSL/SSH Inspection: certificate-inspection" in result
        assert "UTM Inspection" in result
        assert "ENABLED" in result
        assert "Log Traffic: utm" in result
        assert "Log Traffic: No" not in result

    def test_firewall_policy_detail_utm_disabled_with_bound_profile_is_unambiguous(self):
        """A bound-but-inactive profile (utm-status=disable) must not be
        misread as active inspection: both the profile name AND the
        DISABLED state must render."""
        policy_data = {
            "results": {
                "policyid": 36,
                "name": "leftover-binding",
                "action": "accept",
                "utm-status": "disable",
                "av-profile": "default",
            }
        }

        result = FortiGateTemplates.firewall_policy_detail(policy_data, "test_device")

        assert "Antivirus: default" in result
        assert "DISABLED" in result

    def test_firewall_policy_detail_logtraffic_utm_not_rendered_as_no(self):
        """Dedicated regression test for the exact logtraffic="utm" bug,
        independently -k logtraffic-selectable."""
        policy_data = {
            "results": {
                "policyid": 38,
                "name": "logtraffic-only",
                "action": "accept",
                "logtraffic": "utm",
            }
        }

        result = FortiGateTemplates.firewall_policy_detail(policy_data, "test_device")

        assert "Log Traffic: utm" in result
        assert "Log Traffic: No" not in result

    def test_firewall_policy_detail_profile_group_type_documented_not_silent(self):
        """VIS-F4 deferred-gap: profile-type=group must document the group
        binding, not silently render as 'no protection'."""
        policy_data = {
            "results": {
                "policyid": 37,
                "name": "grouped",
                "action": "accept",
                "utm-status": "enable",
                "profile-type": "group",
                "profile-group": "standard-utm-group",
            }
        }

        result = FortiGateTemplates.firewall_policy_detail(policy_data, "test_device")

        assert "standard-utm-group" in result

    def test_address_objects_empty(self):
        """Empty address objects template test"""
        data = {"results": []}
        result = FortiGateTemplates.address_objects(data)
        
        assert "Address Objects" in result
        assert "No address objects found" in result
    
    def test_address_objects_with_data(self):
        """Address objects template test with data"""
        data = {
            "results": [
                {
                    "name": "test_addr",
                    "subnet": "192.168.1.0/24",
                    "type": "ipmask",
                    "comment": "Test address"
                }
            ]
        }
        result = FortiGateTemplates.address_objects(data)
        
        assert "Address Objects" in result
        assert "test_addr" in result
        assert "192.168.1.0/24" in result
    
    def test_service_objects_empty(self):
        """Empty service objects template test"""
        data = {"results": []}
        result = FortiGateTemplates.service_objects(data)
        
        assert "Service Objects" in result
        assert "No service objects found" in result
    
    def test_service_objects_with_data(self):
        """Service objects template test with data"""
        data = {
            "results": [
                {
                    "name": "HTTP",
                    "tcp-portrange": "80",
                    "protocol": "TCP/UDP/SCTP",
                    "comment": "HTTP service"
                }
            ]
        }
        result = FortiGateTemplates.service_objects(data)
        
        assert "Service Objects" in result
        assert "HTTP" in result
        assert "80" in result
    
    def test_static_routes_empty(self):
        """Empty static routes template test"""
        data = {"results": []}
        result = FortiGateTemplates.static_routes(data)
        
        assert "Static Routes" in result
        assert "No static routes found" in result
    
    def test_static_routes_with_data(self):
        """Static routes template test with data"""
        data = {
            "results": [
                {
                    "dst": "10.0.0.0/8",
                    "gateway": "192.168.1.1",
                    "device": "port1",
                    "distance": 10,
                    "status": "enable"
                }
            ]
        }
        result = FortiGateTemplates.static_routes(data)
        
        assert "Static Routes" in result
        assert "10.0.0.0/8" in result
        assert "192.168.1.1" in result
    
    def test_interfaces_empty(self):
        """Empty interfaces template test"""
        data = {"results": []}
        result = FortiGateTemplates.interfaces(data)
        
        assert "Interfaces" in result
        assert "No interfaces found" in result
    
    def test_interfaces_with_data(self):
        """Interfaces template test with data"""
        data = {
            "results": [
                {
                    "name": "port1",
                    "status": "up",
                    "ip": "192.168.1.1 255.255.255.0",
                    "type": "physical",
                    "alias": "LAN"
                }
            ]
        }
        result = FortiGateTemplates.interfaces(data)
        
        assert "Interfaces" in result
        assert "port1" in result
        assert "192.168.1.1" in result
        assert "physical" in result
        assert "LAN" in result
    
    def test_device_status_success(self):
        """Device status template test"""
        device_id = "test_device"
        status_data = {
            "hostname": "FortiGate",
            "version": "v7.0.5",
            "serial": "FGT80FTK20004708",
            "status": "online"
        }
        
        result = FortiGateTemplates.device_status(device_id, status_data)
        
        assert "Device Status" in result
        assert "test_device" in result
        # Template'de status bilgisi farklı şekilde işleniyor
        assert "test_device" in result
    
    def test_vdoms_success(self):
        """VDOMs template test"""
        data = {
            "results": [
                {
                    "name": "root",
                    "enabled": True,
                    "description": "Root VDOM"
                }
            ]
        }
        
        result = FortiGateTemplates.vdoms(data)

        assert "Virtual Domains" in result
        assert "root" in result
        assert "enabled" in result.lower()

    def test_virtual_ips_empty(self):
        """Empty virtual IPs template test"""
        data = {"results": []}
        result = FortiGateTemplates.virtual_ips(data)

        assert "Virtual IPs" in result
        assert "No virtual IPs found" in result

    def test_virtual_ips_renders_list_shaped_mappedip(self):
        """cmdb/firewall/vip GET returns `mappedip` as a table type --
        a list of member objects -- even for VIPs created with a plain
        string. The template must render the range value(s), not the
        raw Python repr of the list."""
        data = {
            "status": "success",
            "vdom": "root",
            "path": "firewall",
            "name": "vip",
            "results": [
                {
                    "name": "web-server-vip",
                    "uuid": "9c4f22aa-1234-51ec-9f44-005056ab0001",
                    "comment": "Web server DNAT",
                    "type": "static-nat",
                    "extip": "203.0.113.10",
                    "extaddr": [],
                    "mappedip": [{"range": "192.168.1.100"}],
                    "extintf": "wan1",
                    "portforward": "enable",
                    "protocol": "tcp",
                    "extport": "8443",
                    "mappedport": "443",
                }
            ],
        }

        result = FortiGateTemplates.virtual_ips(data)

        assert "Virtual IP: web-server-vip" in result
        assert "External IP: 203.0.113.10" in result
        assert "Mapped IP: 192.168.1.100" in result
        assert "{'range'" not in result
        assert "External Interface: wan1" in result
        assert "Port Forwarding: enable" in result
        assert "Protocol: tcp" in result
        assert "External Port: 8443" in result
        assert "Mapped Port: 443" in result
        assert "Comment: Web server DNAT" in result

    def test_virtual_ips_renders_string_mappedip(self):
        """A plain-string mappedip (config echo shape) must render as-is;
        a missing mappedip must fall back to N/A."""
        data = {
            "results": [
                {
                    "name": "legacy-vip",
                    "extip": "203.0.113.20",
                    "mappedip": "10.0.0.20",
                    "extintf": "any",
                    "portforward": "disable",
                },
                {
                    "name": "no-mapped-vip",
                    "extip": "203.0.113.21",
                    "extintf": "any",
                    "portforward": "disable",
                },
            ]
        }

        result = FortiGateTemplates.virtual_ips(data)

        assert "Mapped IP: 10.0.0.20" in result
        assert "Mapped IP: N/A" in result

    def test_virtual_ip_detail_renders_list_shaped_mappedip(self):
        """VIP detail (GET by mkey returns a one-element results list)
        must unwrap the member-list mappedip; multiple members join with
        a comma."""
        data = {
            "status": "success",
            "vdom": "root",
            "path": "firewall",
            "name": "vip",
            "mkey": "range-vip",
            "results": [
                {
                    "name": "range-vip",
                    "uuid": "9c4f22aa-1234-51ec-9f44-005056ab0002",
                    "type": "static-nat",
                    "extip": "203.0.113.30-203.0.113.31",
                    "mappedip": [
                        {"range": "192.168.1.100"},
                        {"range": "192.168.1.101"},
                    ],
                    "extintf": "wan1",
                    "portforward": "disable",
                }
            ],
        }

        result = FortiGateTemplates.virtual_ip_detail(data)

        assert "Virtual IP Detail" in result
        assert "Name: range-vip" in result
        assert "Mapped IP: 192.168.1.100, 192.168.1.101" in result
        assert "{'range'" not in result

    def test_virtual_ip_detail_renders_string_mappedip(self):
        """A plain-string mappedip in a dict-shaped results payload must
        render as-is."""
        data = {
            "results": {
                "name": "legacy-vip",
                "extip": "203.0.113.20",
                "mappedip": "10.0.0.20",
                "extintf": "any",
                "portforward": "disable",
            }
        }

        result = FortiGateTemplates.virtual_ip_detail(data)

        assert "Name: legacy-vip" in result
        assert "Mapped IP: 10.0.0.20" in result

    def test_virtual_ip_detail_not_found(self):
        """Empty results must render the not-found branch."""
        data = {"results": []}

        result = FortiGateTemplates.virtual_ip_detail(data)

        assert "Virtual IP not found" in result

    def test_security_profiles_all_ok_renders_all_categories(self):
        """All 4 categories status ok with profiles renders each title
        and each profile name."""
        data = {
            "antivirus": {"status": "ok", "profiles": [{"name": "av-default", "comment": "AV default"}]},
            "ips": {"status": "ok", "profiles": [{"name": "ips-default"}]},
            "webfilter": {"status": "ok", "profiles": [{"name": "wf-default"}]},
            "application_control": {"status": "ok", "profiles": [{"name": "app-default"}]},
        }

        result = FortiGateTemplates.security_profiles(data)

        assert "Antivirus Profiles" in result
        assert "av-default" in result
        assert "IPS Sensors" in result
        assert "ips-default" in result
        assert "Web Filter Profiles" in result
        assert "wf-default" in result
        assert "Application Control Profiles" in result
        assert "app-default" in result

    def test_security_profiles_error_vs_empty_distinction(self):
        """A per-category authorization/licensing error must never render
        identically to a genuinely empty category."""
        data = {
            "antivirus": {"status": "ok", "profiles": [{"name": "av-default"}]},
            "ips": {"status": "error", "error": "403 Forbidden (feature not licensed)"},
            "webfilter": {"status": "ok", "profiles": []},
            "application_control": {"status": "ok", "profiles": [{"name": "app-default"}]},
        }

        result = FortiGateTemplates.security_profiles(data)

        assert "query failed" in result
        assert "403" in result
        assert "Web Filter Profiles: none configured" in result

        ips_line = next(line for line in result.splitlines() if line.startswith("IPS Sensors"))
        assert "none configured" not in ips_line

    def test_security_profiles_category_not_queried(self):
        """A category key entirely absent renders 'not queried', no
        KeyError/AttributeError."""
        data = {
            "antivirus": {"status": "ok", "profiles": [{"name": "av-default"}]},
        }

        result = FortiGateTemplates.security_profiles(data)

        assert "IPS Sensors: not queried" in result
        assert "Web Filter Profiles: not queried" in result
        assert "Application Control Profiles: not queried" in result

    def test_admin_accounts_with_data(self):
        """Two-admin fixture, one admin's vdom as list-of-dict, the other
        as a bare string; name/accprofile/two-factor/trusted-host all render
        correctly. No assertion on the password field (Phase 9's concern)."""
        data = {
            "results": [
                {
                    "name": "admin",
                    "accprofile": "super_admin",
                    "vdom": [{"name": "root"}],
                    "trusthost1": "198.51.100.0 255.255.255.0",
                    "trusthost2": "0.0.0.0 0.0.0.0",
                    "two-factor": "email",
                    "password": "ENC_FAKE_NOT_REAL_PLACEHOLDER",
                },
                {
                    "name": "readonly_auditor",
                    "accprofile": "prof_readonly",
                    "vdom": "root",
                    "two-factor": "disable",
                    "password": "ENC_FAKE_NOT_REAL_PLACEHOLDER_2",
                },
            ]
        }

        result = FortiGateTemplates.admin_accounts(data)

        assert "admin" in result
        assert "super_admin" in result
        assert "Two-Factor: On" in result
        assert "Trusted Hosts: Yes" in result
        assert "readonly_auditor" in result
        assert "prof_readonly" in result
        assert "Two-Factor: Off" in result
        assert "Trusted Hosts: No" in result
        assert "VDOM: root" in result

    def test_admin_accounts_empty(self):
        """{"results": []} renders 'No administrator accounts configured'."""
        data = {"results": []}

        result = FortiGateTemplates.admin_accounts(data)

        assert "No administrator accounts configured" in result

    def test_admin_accounts_empty_body_fallback(self):
        """{"status": "success"} (no results key) renders the same fallback
        text, never KeyError."""
        data = {"status": "success"}

        result = FortiGateTemplates.admin_accounts(data)

        assert "No administrator accounts configured" in result

    def test_sslvpn_settings_singleton_dict_shape(self):
        """`results` is a single dict, NOT a list -- the template must read
        it as a dict (device_status precedent), never list-index it."""
        data = {
            "http_method": "GET",
            "status": "success",
            "vdom": "root",
            "results": {
                "status": "enable",
                "port": 443,
                "source-interface": [{"name": "wan1"}],
                "tunnel-ip-pools": [{"name": "SSLVPN_TUNNEL_ADDR1"}],
                "default-portal": "full-access",
                "ssl-min-proto-ver": "tls1-2",
                "idle-timeout": 300,
                "auth-timeout": 28800,
                "login-attempt-limit": 2,
                "servercert": "Fortinet_Factory",
            },
        }

        result = FortiGateTemplates.sslvpn_settings(data)

        assert "SSL-VPN" in result
        assert "enable" in result
        assert "wan1" in result
        assert "full-access" in result

    def test_sslvpn_settings_empty_body_fallback(self):
        """{"status": "success"} (no results key) renders "No SSL-VPN
        settings available", never KeyError."""
        data = {"status": "success"}

        result = FortiGateTemplates.sslvpn_settings(data)

        assert "No SSL-VPN settings available" in result

    def test_sslvpn_settings_with_portals_renders_bookmarks(self):
        """settings dict + portals_data with a bookmark-group/bookmarks
        structure renders the bookmark name/apptype/host. No assertion made
        on the password field's presence/absence."""
        settings_data = {
            "results": {
                "status": "enable",
                "port": 443,
            },
        }
        portals_data = {
            "results": [
                {
                    "name": "full-access",
                    "bookmark-group": [
                        {
                            "name": "default-bookmarks",
                            "bookmarks": [
                                {
                                    "name": "internal-rdp",
                                    "apptype": "rdp",
                                    "host": "198.51.100.20",
                                    "logon-password": "ENC_FAKE_BOOKMARK_PW_NOT_REAL",
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        result = FortiGateTemplates.sslvpn_settings(settings_data, portals_data)

        assert "internal-rdp" in result
        assert "rdp" in result
        assert "198.51.100.20" in result

    def test_sslvpn_settings_without_portals_omits_bookmarks(self):
        """portals_data omitted (default None) must not crash and must not
        render a Portal Bookmarks section."""
        settings_data = {
            "results": {
                "status": "enable",
                "port": 443,
            },
        }

        result = FortiGateTemplates.sslvpn_settings(settings_data)

        assert "Portal Bookmarks" not in result

    def test_local_in_policies_with_data(self):
        """A 2-rule fixture; policyid, interface name, action all render."""
        data = {
            "results": [
                {
                    "policyid": 1,
                    "intf": [{"name": "wan1"}],
                    "srcaddr": [{"name": "MGMT-SUBNET"}],
                    "dstaddr": [{"name": "all"}],
                    "action": "accept",
                    "service": [{"name": "HTTPS"}, {"name": "SSH"}],
                    "status": "enable",
                    "comments": "Allow mgmt access to GUI/CLI",
                },
                {
                    "policyid": 2,
                    "intf": [{"name": "any"}],
                    "srcaddr": [{"name": "all"}],
                    "dstaddr": [{"name": "all"}],
                    "action": "deny",
                    "service": [{"name": "ALL"}],
                    "status": "enable",
                },
            ]
        }

        result = FortiGateTemplates.local_in_policies(data)

        assert "Policy 1" in result
        assert "wan1" in result
        assert "accept" in result
        assert "Policy 2" in result
        assert "deny" in result

    def test_local_in_policies_empty(self):
        """{"results": []} renders 'No local-in policies configured'."""
        data = {"results": []}

        result = FortiGateTemplates.local_in_policies(data)

        assert "No local-in policies configured" in result

    def test_local_in_policies_empty_body_fallback(self):
        """{"status": "success"} (no results key) renders the same fallback
        text, never KeyError."""
        data = {"status": "success"}

        result = FortiGateTemplates.local_in_policies(data)

        assert "No local-in policies configured" in result


class TestRoutingTableTemplate:
    """routing_table template -- monitor/router/ipv4 field names.

    Fixtures use the keys FortiOS v7.6.7 actually returns (ip_mask,
    gateway, interface, distance, metric, priority, type, origin), verified
    against a live device. The destination is ``ip_mask``; ``dst`` is the
    cmdb/router/static spelling and does not appear in this response.
    """

    def test_routing_table_empty(self):
        result = FortiGateTemplates.routing_table({"results": []})

        assert "Routing Table" in result
        assert "No routes found" in result

    def test_destination_prefix_is_read_from_ip_mask(self):
        """Regression guard: reading ``dst`` rendered every row as
        "Route: N/A", so the tool reported a routing table with no
        identifiable destinations."""
        data = {
            "results": [
                {
                    "ip_mask": "0.0.0.0/0",
                    "gateway": "203.0.113.254",
                    "interface": "wan1",
                    "distance": 5,
                    "metric": 0,
                    "priority": 1,
                    "type": "static",
                    "origin": "dhcp",
                }
            ]
        }

        result = FortiGateTemplates.routing_table(data)

        assert "Route: 0.0.0.0/0" in result
        assert "Route: N/A" not in result
        assert "Gateway: 203.0.113.254" in result
        assert "Interface: wan1" in result
        assert "Distance: 5" in result
        assert "Metric: 0" in result
        assert "Priority: 1" in result
        assert "Type: static" in result

    def test_origin_distinguishes_dhcp_learned_from_configured_route(self):
        """Both report type "static"; only ``origin`` separates them."""
        data = {
            "results": [
                {"ip_mask": "0.0.0.0/0", "type": "static", "origin": "dhcp"},
                {"ip_mask": "10.0.0.0/8", "type": "static"},
            ]
        }

        result = FortiGateTemplates.routing_table(data)

        assert "Origin: dhcp" in result
        assert result.count("Origin:") == 1

    def test_connected_route_renders_without_optional_fields(self):
        data = {"results": [{"ip_mask": "10.10.20.0/24", "interface": "VLAN_20",
                             "gateway": "0.0.0.0", "type": "connect"}]}

        result = FortiGateTemplates.routing_table(data)

        assert "Route: 10.10.20.0/24" in result
        assert "Type: connect" in result

    def test_legacy_dst_key_is_not_silently_accepted(self):
        """A payload carrying only the old ``dst`` key must NOT render as a
        resolved destination -- otherwise a future regression to the wrong
        field name would look correct in tests."""
        result = FortiGateTemplates.routing_table({"results": [{"dst": "0.0.0.0/0"}]})

        assert "Route: N/A" in result

class TestFortiGateFormatters:
    """FortiGate Formatters test class"""

    def test_format_firewall_policies(self):
        """Firewall policies formatter test"""
        data = {
            "results": [
                {
                    "policyid": 1,
                    "name": "Test_Policy",
                    "action": "accept"
                }
            ]
        }
        
        result = FortiGateFormatters.format_firewall_policies(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Firewall Policies" in result[0].text
    
    def test_format_firewall_policy_detail(self):
        """Firewall policy detail formatter test"""
        policy_data = {
            "results": {
                "policyid": 35,
                "name": "Test_Policy",
                "action": "accept"
            }
        }
        
        result = FortiGateFormatters.format_firewall_policy_detail(
            policy_data, "test_device"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Policy Detail" in result[0].text
    
    def test_format_address_objects(self):
        """Address objects formatter test"""
        data = {
            "results": [
                {
                    "name": "test_addr",
                    "subnet": "192.168.1.0/24"
                }
            ]
        }
        
        result = FortiGateFormatters.format_address_objects(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Address Objects" in result[0].text
    
    def test_format_service_objects(self):
        """Service objects formatter test"""
        data = {
            "results": [
                {
                    "name": "HTTP",
                    "tcp-portrange": "80"
                }
            ]
        }
        
        result = FortiGateFormatters.format_service_objects(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Service Objects" in result[0].text
    
    def test_format_static_routes(self):
        """Static routes formatter test"""
        data = {
            "results": [
                {
                    "dst": "10.0.0.0/8",
                    "gateway": "192.168.1.1"
                }
            ]
        }
        
        result = FortiGateFormatters.format_static_routes(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Static Routes" in result[0].text
    
    def test_format_interfaces(self):
        """Interfaces formatter test"""
        data = {
            "results": [
                {
                    "name": "port1",
                    "status": "up"
                }
            ]
        }
        
        result = FortiGateFormatters.format_interfaces(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Network Interfaces" in result[0].text

    def test_format_virtual_ips(self):
        """Virtual IPs formatter test with a realistic list-shaped
        mappedip (cmdb/firewall/vip GET shape)."""
        data = {
            "status": "success",
            "results": [
                {
                    "name": "web-server-vip",
                    "extip": "203.0.113.10",
                    "mappedip": [{"range": "192.168.1.100"}],
                    "extintf": "wan1",
                    "portforward": "disable",
                }
            ],
        }

        result = FortiGateFormatters.format_virtual_ips(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Virtual IPs" in result[0].text
        assert "Mapped IP: 192.168.1.100" in result[0].text
        assert "{'range'" not in result[0].text

    def test_format_virtual_ip_detail(self):
        """Virtual IP detail formatter test with a realistic list-shaped
        mappedip (cmdb/firewall/vip GET-by-mkey shape)."""
        data = {
            "status": "success",
            "results": [
                {
                    "name": "web-server-vip",
                    "extip": "203.0.113.10",
                    "mappedip": [{"range": "192.168.1.100"}],
                    "extintf": "wan1",
                    "portforward": "disable",
                }
            ],
        }

        result = FortiGateFormatters.format_virtual_ip_detail(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Virtual IP Detail" in result[0].text
        assert "Mapped IP: 192.168.1.100" in result[0].text
        assert "{'range'" not in result[0].text

    def test_format_error(self):
        """Error formatter test"""
        result = FortiGateFormatters.format_error_response(
            "test_operation", "test_device", "Test error message"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Error" in result[0].text
        assert "Test error message" in result[0].text
        assert "test_device" in result[0].text
        assert "test_operation" in result[0].text
    
    def test_format_operation_result_success(self):
        """Success operation result formatter test"""
        result = FortiGateFormatters.format_operation_result(
            "test_operation", "test_device", True, "Success details"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "test_operation" in result[0].text
        assert "test_device" in result[0].text
        assert "Success details" in result[0].text
    
    def test_format_operation_result_failure(self):
        """Failure operation result formatter test"""
        result = FortiGateFormatters.format_operation_result(
            "test_operation", "test_device", False,
            error="Operation failed"
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "test_operation" in result[0].text
        assert "test_device" in result[0].text
        assert "Operation failed" in result[0].text

    def test_format_security_profiles(self):
        """Security profiles formatter test"""
        data = {
            "antivirus": {"status": "ok", "profiles": [{"name": "av-default"}]},
        }

        result = FortiGateFormatters.format_security_profiles(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Security Profiles" in result[0].text

    def test_format_admin_accounts(self):
        """Admin accounts formatter test"""
        data = {
            "results": [
                {
                    "name": "admin",
                    "accprofile": "super_admin",
                }
            ]
        }

        result = FortiGateFormatters.format_admin_accounts(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Administrator Accounts" in result[0].text

    def test_format_sslvpn_settings(self):
        """SSL-VPN settings formatter test"""
        data = {
            "results": {
                "status": "enable",
                "port": 443,
            }
        }

        result = FortiGateFormatters.format_sslvpn_settings(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "SSL-VPN Settings" in result[0].text

    def test_format_local_in_policies(self):
        """Local-in policies formatter test"""
        data = {
            "results": [
                {
                    "policyid": 1,
                    "action": "accept",
                }
            ]
        }

        result = FortiGateFormatters.format_local_in_policies(data)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Local-In Policies" in result[0].text

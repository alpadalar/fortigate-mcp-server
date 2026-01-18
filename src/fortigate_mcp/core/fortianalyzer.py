"""
FortiAnalyzer API management for the MCP server.

This module provides FortiAnalyzer JSON-RPC API integration:
- Session management with authentication
- Log search and retrieval
- Report generation and download
- FortiView analytics
- Event and alert management
"""
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import httpx
import json
from .logging import get_logger, log_api_call


class FortiAnalyzerAPIError(Exception):
    """Custom exception for FortiAnalyzer API errors."""

    def __init__(self, message: str, error_code: Optional[int] = None):
        super().__init__(message)
        self.error_code = error_code


class FortiAnalyzerAPI:
    """FortiAnalyzer JSON-RPC API client.

    Handles all communication with FortiAnalyzer:
    - Session-based authentication
    - JSON-RPC request/response processing
    - Log search and analytics
    - Report management
    """

    def __init__(
        self,
        host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 30,
        adom: str = "root"
    ):
        """Initialize FortiAnalyzer API client.

        Args:
            host: FortiAnalyzer hostname or IP
            api_token: API token for authentication
            username: Username for session authentication
            password: Password for session authentication
            port: HTTPS port (default 443)
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            adom: Administrative Domain (default "root")
        """
        self.host = host
        self.port = port
        self.api_token = api_token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.adom = adom

        self.base_url = f"https://{host}:{port}/jsonrpc"
        self.session_id: Optional[str] = None
        self.request_id = 1
        self.logger = get_logger("fortianalyzer")

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        self.logger.info(f"Initialized FortiAnalyzer API client for {host}")

    def _get_request_id(self) -> int:
        """Get next request ID for JSON-RPC."""
        req_id = self.request_id
        self.request_id += 1
        return req_id

    def _make_request(
        self,
        method: str,
        params: Optional[List[Dict]] = None,
        url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make JSON-RPC request to FortiAnalyzer.

        Args:
            method: JSON-RPC method name
            params: List of parameter dictionaries
            url: URL path within params (for API calls)

        Returns:
            API response data

        Raises:
            FortiAnalyzerAPIError: If request fails
        """
        if params is None:
            params = [{}]

        # Add session ID if we have one (not needed for login)
        if self.session_id and method != "exec":
            for param in params:
                if "session" not in param:
                    param["session"] = self.session_id
        elif self.session_id:
            # For exec method, session goes in first param
            if params and "session" not in params[0]:
                params[0]["session"] = self.session_id

        payload = {
            "id": self._get_request_id(),
            "method": method,
            "params": params
        }

        # Add API token to headers if using token auth
        headers = self.headers.copy()
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        start_time = time.time()

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=self.timeout
            ) as client:
                response = client.post(
                    self.base_url,
                    headers=headers,
                    json=payload
                )

                duration_ms = (time.time() - start_time) * 1000
                log_api_call(self.logger, "POST", method, response.status_code, duration_ms)

                if response.status_code != 200:
                    raise FortiAnalyzerAPIError(
                        f"HTTP error: {response.status_code}",
                        error_code=response.status_code
                    )

                result = response.json()

                # Check for JSON-RPC error
                if "error" in result and result["error"]:
                    error = result["error"]
                    raise FortiAnalyzerAPIError(
                        f"API error: {error.get('message', str(error))}",
                        error_code=error.get("code")
                    )

                # Check result status
                if "result" in result:
                    res_data = result["result"]
                    if isinstance(res_data, list) and len(res_data) > 0:
                        status = res_data[0].get("status", {})
                        if isinstance(status, dict) and status.get("code", 0) != 0:
                            raise FortiAnalyzerAPIError(
                                f"API error: {status.get('message', 'Unknown error')}",
                                error_code=status.get("code")
                            )
                        return res_data[0]
                    return res_data

                return result

        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, "POST", method, None, duration_ms)
            raise FortiAnalyzerAPIError(f"Network error: {str(e)}")

    def login(self) -> bool:
        """Login to FortiAnalyzer and establish session.

        Returns:
            True if login successful

        Raises:
            FortiAnalyzerAPIError: If login fails
        """
        if self.api_token:
            # Token auth doesn't need explicit login
            self.logger.info("Using API token authentication")
            return True

        if not self.username or not self.password:
            raise FortiAnalyzerAPIError("Username and password required for session auth")

        params = [{
            "url": "/sys/login/user",
            "data": {
                "user": self.username,
                "passwd": self.password
            }
        }]

        result = self._make_request("exec", params)

        if "session" in result:
            self.session_id = result["session"]
            self.logger.info("Login successful")
            return True

        raise FortiAnalyzerAPIError("Login failed: no session returned")

    def logout(self) -> bool:
        """Logout from FortiAnalyzer.

        Returns:
            True if logout successful
        """
        if not self.session_id:
            return True

        try:
            params = [{
                "url": "/sys/logout",
                "session": self.session_id
            }]
            self._make_request("exec", params)
            self.session_id = None
            self.logger.info("Logout successful")
            return True
        except Exception as e:
            self.logger.warning(f"Logout error: {e}")
            self.session_id = None
            return False

    def test_connection(self) -> bool:
        """Test connection to FortiAnalyzer.

        Returns:
            True if connection successful
        """
        try:
            self.get_system_status()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    # ==================== System endpoints ====================

    def get_system_status(self) -> Dict[str, Any]:
        """Get FortiAnalyzer system status."""
        params = [{
            "url": "/sys/status"
        }]
        return self._make_request("get", params)

    def get_adoms(self) -> Dict[str, Any]:
        """Get list of Administrative Domains."""
        params = [{
            "url": "/dvmdb/adom"
        }]
        return self._make_request("get", params)

    # ==================== Device management ====================

    def get_devices(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get devices reporting logs to FortiAnalyzer.

        Args:
            adom: Administrative Domain (uses default if not specified)
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device"
        }]
        return self._make_request("get", params)

    def get_device_detail(self, device_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed device information.

        Args:
            device_name: Device name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device/{device_name}"
        }]
        return self._make_request("get", params)

    def get_device_status(self, device_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get device log status.

        Args:
            device_name: Device name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device/{device_name}",
            "fields": ["name", "hostname", "ip", "conn_status", "log_status",
                      "os_type", "os_ver", "platform_str", "sn", "last_log_time"]
        }]
        return self._make_request("get", params)

    def get_all_devices_status(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get status for all devices reporting logs.

        Args:
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device",
            "fields": ["name", "hostname", "ip", "conn_status", "log_status",
                      "os_type", "os_ver", "platform_str", "sn", "last_log_time"]
        }]
        return self._make_request("get", params)

    # ==================== Log operations ====================

    def _parse_time_range(self, time_range: Optional[str] = None) -> tuple:
        """Parse time range string into start/end timestamps.

        Args:
            time_range: Time range (e.g., "1h", "24h", "7d", "30d") or None for last hour

        Returns:
            Tuple of (start_time, end_time) as ISO format strings
        """
        now = datetime.utcnow()
        end_time = now.strftime("%Y-%m-%d %H:%M:%S")

        if not time_range:
            time_range = "1h"

        # Parse relative time ranges
        if time_range.endswith("m"):
            minutes = int(time_range[:-1])
            start = now - timedelta(minutes=minutes)
        elif time_range.endswith("h"):
            hours = int(time_range[:-1])
            start = now - timedelta(hours=hours)
        elif time_range.endswith("d"):
            days = int(time_range[:-1])
            start = now - timedelta(days=days)
        elif time_range == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif time_range == "yesterday":
            yesterday = now - timedelta(days=1)
            start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            end_time = yesterday.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Default to last hour
            start = now - timedelta(hours=1)

        start_time = start.strftime("%Y-%m-%d %H:%M:%S")
        return start_time, end_time

    def search_logs(
        self,
        adom: Optional[str] = None,
        log_type: str = "traffic",
        filter_expr: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Search logs with filters.

        Args:
            adom: Administrative Domain
            log_type: Log type (traffic, event, security, app-ctrl, webfilter, etc.)
            filter_expr: Filter expression (e.g., "srcip=10.0.0.1 dstport=443")
            time_range: Time range (e.g., "1h", "24h", "7d", "30d")
            limit: Maximum number of results (default 100)
            offset: Offset for pagination
            device: Filter by device name

        Returns:
            Dictionary with log search results
        """
        adom = adom or self.adom
        start_time, end_time = self._parse_time_range(time_range)

        # Build filter
        filters = []
        if filter_expr:
            filters.append(filter_expr)
        if device:
            filters.append(f"devname={device}")

        data = {
            "logtype": log_type,
            "time-range": {
                "start": start_time,
                "end": end_time
            },
            "limit": limit,
            "offset": offset
        }

        if filters:
            data["filter"] = " and ".join(filters)

        params = [{
            "url": f"/logview/adom/{adom}/logsearch",
            "data": data
        }]
        return self._make_request("add", params)

    def get_log_search_results(
        self,
        adom: Optional[str] = None,
        tid: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get results from a log search task.

        Args:
            adom: Administrative Domain
            tid: Task ID from search_logs

        Returns:
            Dictionary with search results
        """
        adom = adom or self.adom
        params = [{
            "url": f"/logview/adom/{adom}/logsearch/{tid}"
        }]
        return self._make_request("get", params)

    def get_log_stats(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get log statistics and volume metrics.

        Args:
            adom: Administrative Domain
            time_range: Time range for stats

        Returns:
            Dictionary with log statistics
        """
        adom = adom or self.adom
        start_time, end_time = self._parse_time_range(time_range)

        params = [{
            "url": f"/logview/adom/{adom}/logstats",
            "data": {
                "time-range": {
                    "start": start_time,
                    "end": end_time
                }
            }
        }]
        return self._make_request("get", params)

    def get_log_fields(
        self,
        adom: Optional[str] = None,
        log_type: str = "traffic"
    ) -> Dict[str, Any]:
        """Get available log fields for a log type.

        Args:
            adom: Administrative Domain
            log_type: Log type

        Returns:
            Dictionary with available fields
        """
        adom = adom or self.adom
        params = [{
            "url": f"/logview/adom/{adom}/logfields/{log_type}"
        }]
        return self._make_request("get", params)

    def get_raw_logs(
        self,
        adom: Optional[str] = None,
        log_type: str = "traffic",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        device: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get raw log data for a time range.

        Args:
            adom: Administrative Domain
            log_type: Log type
            start_time: Start time (ISO format)
            end_time: End time (ISO format)
            limit: Maximum results
            device: Filter by device

        Returns:
            Dictionary with raw logs
        """
        adom = adom or self.adom

        if not start_time or not end_time:
            start_time, end_time = self._parse_time_range("1h")

        data = {
            "logtype": log_type,
            "time-range": {
                "start": start_time,
                "end": end_time
            },
            "limit": limit
        }

        if device:
            data["filter"] = f"devname={device}"

        params = [{
            "url": f"/logview/adom/{adom}/logfiles/data",
            "data": data
        }]
        return self._make_request("get", params)

    # ==================== Report operations ====================

    def list_reports(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """List available report templates.

        Args:
            adom: Administrative Domain

        Returns:
            Dictionary with report templates
        """
        adom = adom or self.adom
        params = [{
            "url": f"/report/adom/{adom}/config/report"
        }]
        return self._make_request("get", params)

    def get_report_detail(
        self,
        report_name: str,
        adom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get report template details.

        Args:
            report_name: Report template name
            adom: Administrative Domain

        Returns:
            Dictionary with report details
        """
        adom = adom or self.adom
        params = [{
            "url": f"/report/adom/{adom}/config/report/{report_name}"
        }]
        return self._make_request("get", params)

    def run_report(
        self,
        report_name: str,
        adom: Optional[str] = None,
        devices: Optional[List[str]] = None,
        time_range: Optional[str] = None,
        output_format: str = "pdf"
    ) -> Dict[str, Any]:
        """Run a report.

        Args:
            report_name: Report template name
            adom: Administrative Domain
            devices: List of devices to include
            time_range: Time range for report data
            output_format: Output format (pdf, html, csv)

        Returns:
            Dictionary with task ID for report generation
        """
        adom = adom or self.adom
        start_time, end_time = self._parse_time_range(time_range)

        data = {
            "report": report_name,
            "format": output_format,
            "time-range": {
                "start": start_time,
                "end": end_time
            }
        }

        if devices:
            data["devices"] = [{"name": d} for d in devices]

        params = [{
            "url": f"/report/adom/{adom}/run",
            "data": data
        }]
        return self._make_request("exec", params)

    def get_report_status(
        self,
        task_id: int,
        adom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get report generation status.

        Args:
            task_id: Report task ID
            adom: Administrative Domain

        Returns:
            Dictionary with report status
        """
        adom = adom or self.adom
        params = [{
            "url": f"/report/adom/{adom}/run/{task_id}"
        }]
        return self._make_request("get", params)

    def download_report(
        self,
        task_id: int,
        adom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Download completed report.

        Args:
            task_id: Report task ID
            adom: Administrative Domain

        Returns:
            Dictionary with report download URL or content
        """
        adom = adom or self.adom
        params = [{
            "url": f"/report/adom/{adom}/run/{task_id}/download"
        }]
        return self._make_request("get", params)

    def list_report_schedules(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """List report schedules.

        Args:
            adom: Administrative Domain

        Returns:
            Dictionary with scheduled reports
        """
        adom = adom or self.adom
        params = [{
            "url": f"/report/adom/{adom}/config/schedule"
        }]
        return self._make_request("get", params)

    # ==================== FortiView analytics ====================

    def get_fortiview_data(
        self,
        view_type: str,
        adom: Optional[str] = None,
        time_range: Optional[str] = None,
        filter_expr: Optional[str] = None,
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get FortiView dashboard data.

        Args:
            view_type: View type (e.g., "traffic", "threat", "application",
                      "source", "destination", "country", "policy")
            adom: Administrative Domain
            time_range: Time range
            filter_expr: Filter expression
            limit: Maximum results

        Returns:
            Dictionary with FortiView data
        """
        adom = adom or self.adom
        start_time, end_time = self._parse_time_range(time_range)

        data = {
            "time-range": {
                "start": start_time,
                "end": end_time
            },
            "limit": limit
        }

        if filter_expr:
            data["filter"] = filter_expr

        params = [{
            "url": f"/fortiview/adom/{adom}/{view_type}/run",
            "data": data
        }]
        return self._make_request("add", params)

    def get_threat_stats(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get threat statistics and trends.

        Args:
            adom: Administrative Domain
            time_range: Time range

        Returns:
            Dictionary with threat statistics
        """
        adom = adom or self.adom
        start_time, end_time = self._parse_time_range(time_range)

        params = [{
            "url": f"/fortiview/adom/{adom}/threat/run",
            "data": {
                "time-range": {
                    "start": start_time,
                    "end": end_time
                },
                "limit": 100
            }
        }]
        return self._make_request("add", params)

    def get_top_sources(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get top traffic sources.

        Args:
            adom: Administrative Domain
            time_range: Time range
            limit: Number of top sources

        Returns:
            Dictionary with top sources
        """
        return self.get_fortiview_data(
            view_type="fgt-policy-src",
            adom=adom,
            time_range=time_range,
            limit=limit
        )

    def get_top_destinations(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get top traffic destinations.

        Args:
            adom: Administrative Domain
            time_range: Time range
            limit: Number of top destinations

        Returns:
            Dictionary with top destinations
        """
        return self.get_fortiview_data(
            view_type="fgt-policy-dst",
            adom=adom,
            time_range=time_range,
            limit=limit
        )

    def get_top_applications(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get top applications by traffic.

        Args:
            adom: Administrative Domain
            time_range: Time range
            limit: Number of top applications

        Returns:
            Dictionary with top applications
        """
        return self.get_fortiview_data(
            view_type="application",
            adom=adom,
            time_range=time_range,
            limit=limit
        )

    def get_top_threats(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get top threats.

        Args:
            adom: Administrative Domain
            time_range: Time range
            limit: Number of top threats

        Returns:
            Dictionary with top threats
        """
        return self.get_fortiview_data(
            view_type="threat",
            adom=adom,
            time_range=time_range,
            limit=limit
        )

    # ==================== Event management ====================

    def get_event_summary(
        self,
        adom: Optional[str] = None,
        time_range: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get event summary and counts.

        Args:
            adom: Administrative Domain
            time_range: Time range

        Returns:
            Dictionary with event summary
        """
        adom = adom or self.adom
        start_time, end_time = self._parse_time_range(time_range)

        params = [{
            "url": f"/eventmgmt/adom/{adom}/summary",
            "data": {
                "time-range": {
                    "start": start_time,
                    "end": end_time
                }
            }
        }]
        return self._make_request("get", params)

    def list_alerts(
        self,
        adom: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """List active alerts.

        Args:
            adom: Administrative Domain
            severity: Filter by severity (critical, high, medium, low)
            status: Filter by status (unread, read, acknowledged)
            limit: Maximum alerts to return

        Returns:
            Dictionary with alerts
        """
        adom = adom or self.adom

        data = {
            "limit": limit
        }

        filters = []
        if severity:
            filters.append(f"severity={severity}")
        if status:
            filters.append(f"status={status}")

        if filters:
            data["filter"] = " and ".join(filters)

        params = [{
            "url": f"/eventmgmt/adom/{adom}/alerts",
            "data": data
        }]
        return self._make_request("get", params)

    def get_alert_detail(
        self,
        alert_id: str,
        adom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get alert details.

        Args:
            alert_id: Alert ID
            adom: Administrative Domain

        Returns:
            Dictionary with alert details
        """
        adom = adom or self.adom
        params = [{
            "url": f"/eventmgmt/adom/{adom}/alerts/{alert_id}"
        }]
        return self._make_request("get", params)

    def acknowledge_alert(
        self,
        alert_id: str,
        adom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Acknowledge an alert.

        Args:
            alert_id: Alert ID
            adom: Administrative Domain

        Returns:
            Dictionary with acknowledgment result
        """
        adom = adom or self.adom
        params = [{
            "url": f"/eventmgmt/adom/{adom}/alerts/{alert_id}",
            "data": {
                "status": "acknowledged"
            }
        }]
        return self._make_request("set", params)

    def get_event_handlers(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get configured event handlers.

        Args:
            adom: Administrative Domain

        Returns:
            Dictionary with event handlers
        """
        adom = adom or self.adom
        params = [{
            "url": f"/eventmgmt/adom/{adom}/handler"
        }]
        return self._make_request("get", params)

    # ==================== Task management ====================

    def get_task_status(self, task_id: int) -> Dict[str, Any]:
        """Get status of an asynchronous task.

        Args:
            task_id: Task ID

        Returns:
            Dictionary with task status
        """
        params = [{
            "url": f"/task/task/{task_id}"
        }]
        return self._make_request("get", params)


class FortiAnalyzerManager:
    """Manager for FortiAnalyzer instances.

    Handles FortiAnalyzer registration and provides unified access.
    """

    def __init__(self):
        """Initialize FortiAnalyzer manager."""
        self.analyzers: Dict[str, FortiAnalyzerAPI] = {}
        self.logger = get_logger("fortianalyzer_manager")

    def add_analyzer(
        self,
        analyzer_id: str,
        host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 30,
        adom: str = "root"
    ) -> FortiAnalyzerAPI:
        """Add a FortiAnalyzer instance.

        Args:
            analyzer_id: Unique identifier for this FortiAnalyzer
            host: FortiAnalyzer hostname or IP
            api_token: API token for authentication
            username: Username for session authentication
            password: Password for session authentication
            port: HTTPS port
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            adom: Default Administrative Domain

        Returns:
            FortiAnalyzerAPI instance
        """
        if analyzer_id in self.analyzers:
            raise ValueError(f"Analyzer '{analyzer_id}' already exists")

        faz = FortiAnalyzerAPI(
            host=host,
            api_token=api_token,
            username=username,
            password=password,
            port=port,
            verify_ssl=verify_ssl,
            timeout=timeout,
            adom=adom
        )

        self.analyzers[analyzer_id] = faz
        self.logger.info(f"Added FortiAnalyzer: {analyzer_id}")
        return faz

    def get_analyzer(self, analyzer_id: str) -> FortiAnalyzerAPI:
        """Get FortiAnalyzer API client.

        Args:
            analyzer_id: Analyzer identifier

        Returns:
            FortiAnalyzerAPI instance
        """
        if analyzer_id not in self.analyzers:
            raise ValueError(f"Analyzer '{analyzer_id}' not found")
        return self.analyzers[analyzer_id]

    def remove_analyzer(self, analyzer_id: str) -> None:
        """Remove a FortiAnalyzer instance.

        Args:
            analyzer_id: Analyzer identifier to remove
        """
        if analyzer_id not in self.analyzers:
            raise ValueError(f"Analyzer '{analyzer_id}' not found")

        # Try to logout cleanly
        try:
            self.analyzers[analyzer_id].logout()
        except:
            pass

        del self.analyzers[analyzer_id]
        self.logger.info(f"Removed FortiAnalyzer: {analyzer_id}")

    def list_analyzers(self) -> List[str]:
        """List all registered FortiAnalyzer IDs.

        Returns:
            List of analyzer identifiers
        """
        return list(self.analyzers.keys())

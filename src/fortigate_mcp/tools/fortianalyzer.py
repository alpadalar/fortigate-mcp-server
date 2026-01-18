"""
FortiAnalyzer tools for the MCP server.

This module provides MCP tools for FortiAnalyzer management:
- Log search and retrieval
- Report generation and download
- FortiView analytics
- Event and alert management
"""
import json
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from ..core.fortianalyzer import FortiAnalyzerAPI, FortiAnalyzerAPIError, FortiAnalyzerManager
from ..core.logging import get_logger


class FortiAnalyzerTool:
    """Base class for FortiAnalyzer MCP tools."""

    def __init__(self, faz_manager: FortiAnalyzerManager):
        """Initialize the tool.

        Args:
            faz_manager: FortiAnalyzerManager instance
        """
        self.faz_manager = faz_manager
        self.logger = get_logger(f"tools.{self.__class__.__name__.lower()}")

    def _get_analyzer(self, analyzer_id: str) -> FortiAnalyzerAPI:
        """Get FortiAnalyzer API client.

        Args:
            analyzer_id: Analyzer identifier

        Returns:
            FortiAnalyzerAPI instance
        """
        return self.faz_manager.get_analyzer(analyzer_id)

    def _format_response(self, data: Any, title: Optional[str] = None) -> List[Content]:
        """Format response data into MCP content.

        Args:
            data: Data to format
            title: Optional title for the response

        Returns:
            List of Content objects
        """
        if title:
            text = f"**{title}**\n\n```json\n{json.dumps(data, indent=2, default=str)}\n```"
        else:
            text = f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
        return [Content(type="text", text=text)]

    def _format_error(self, operation: str, analyzer_id: str, error: str) -> List[Content]:
        """Format error response.

        Args:
            operation: Operation that failed
            analyzer_id: Analyzer identifier
            error: Error message

        Returns:
            List of Content objects
        """
        text = f"""Error

{{
  "operation": "{operation}",
  "analyzer_id": "{analyzer_id}",
  "error": "{error}",
  "status": "failed"
}}"""
        return [Content(type="text", text=text)]

    def _handle_error(self, operation: str, analyzer_id: str, error: Exception) -> List[Content]:
        """Handle and format errors.

        Args:
            operation: Operation that failed
            analyzer_id: Analyzer identifier
            error: Exception that occurred

        Returns:
            List of Content objects
        """
        error_msg = str(error)
        self.logger.error(f"Failed to {operation} on {analyzer_id}: {error_msg}")

        if isinstance(error, FortiAnalyzerAPIError):
            if error.error_code == -11:
                error_msg = "Authentication failed. Check API token or credentials."
            elif error.error_code == -6:
                error_msg = "Invalid parameter or resource not found."

        return self._format_error(operation, analyzer_id, error_msg)


class FortiAnalyzerTools(FortiAnalyzerTool):
    """FortiAnalyzer MCP tools implementation."""

    # ==================== Analyzer management ====================

    def list_analyzers(self) -> List[Content]:
        """List registered FortiAnalyzer instances.

        Returns:
            List of Content objects with analyzer list
        """
        analyzers = self.faz_manager.list_analyzers()
        if not analyzers:
            return [Content(type="text", text="No FortiAnalyzer instances registered")]

        lines = ["**Registered FortiAnalyzer Instances**", ""]
        for faz_id in analyzers:
            lines.append(f"  - {faz_id}")
        return [Content(type="text", text="\n".join(lines))]

    def add_analyzer(
        self,
        analyzer_id: str,
        host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = False,
        adom: str = "root"
    ) -> List[Content]:
        """Add a FortiAnalyzer instance.

        Args:
            analyzer_id: Unique identifier
            host: FortiAnalyzer hostname
            api_token: API token
            username: Username (if not using token)
            password: Password (if not using token)
            port: HTTPS port
            verify_ssl: Verify SSL certificates
            adom: Default ADOM

        Returns:
            List of Content objects
        """
        try:
            self.faz_manager.add_analyzer(
                analyzer_id=analyzer_id,
                host=host,
                api_token=api_token,
                username=username,
                password=password,
                port=port,
                verify_ssl=verify_ssl,
                adom=adom
            )
            return [Content(type="text", text=f"FortiAnalyzer '{analyzer_id}' added successfully")]
        except Exception as e:
            return self._handle_error("add analyzer", analyzer_id, e)

    def remove_analyzer(self, analyzer_id: str) -> List[Content]:
        """Remove a FortiAnalyzer instance.

        Args:
            analyzer_id: Analyzer identifier

        Returns:
            List of Content objects
        """
        try:
            self.faz_manager.remove_analyzer(analyzer_id)
            return [Content(type="text", text=f"FortiAnalyzer '{analyzer_id}' removed successfully")]
        except Exception as e:
            return self._handle_error("remove analyzer", analyzer_id, e)

    def test_connection(self, analyzer_id: str) -> List[Content]:
        """Test FortiAnalyzer connection.

        Args:
            analyzer_id: Analyzer identifier

        Returns:
            List of Content objects
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            success = faz.test_connection()
            if success:
                return [Content(type="text", text=f"Connection to '{analyzer_id}' successful")]
            else:
                return [Content(type="text", text=f"Connection to '{analyzer_id}' failed")]
        except Exception as e:
            return self._handle_error("test connection", analyzer_id, e)

    # ==================== System information ====================

    def get_system_status(self, analyzer_id: str) -> List[Content]:
        """Get FortiAnalyzer system status.

        Args:
            analyzer_id: Analyzer identifier

        Returns:
            List of Content objects with system status
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            status = faz.get_system_status()
            return self._format_response(status, "FortiAnalyzer System Status")
        except Exception as e:
            return self._handle_error("get system status", analyzer_id, e)

    def get_adoms(self, analyzer_id: str) -> List[Content]:
        """Get list of Administrative Domains.

        Args:
            analyzer_id: Analyzer identifier

        Returns:
            List of Content objects with ADOMs
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            adoms = faz.get_adoms()
            return self._format_response(adoms, "Administrative Domains")
        except Exception as e:
            return self._handle_error("get adoms", analyzer_id, e)

    # ==================== Device management ====================

    def get_devices(self, analyzer_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get devices reporting logs.

        Args:
            analyzer_id: Analyzer identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with devices
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            devices = faz.get_devices(adom)
            return self._format_response(devices, "Devices Reporting Logs")
        except Exception as e:
            return self._handle_error("get devices", analyzer_id, e)

    def get_device_status(
        self,
        analyzer_id: str,
        device_name: str,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get device log status.

        Args:
            analyzer_id: Analyzer identifier
            device_name: Device name
            adom: Administrative Domain

        Returns:
            List of Content objects with device status
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            status = faz.get_device_status(device_name, adom)
            return self._format_response(status, f"Device Status: {device_name}")
        except Exception as e:
            return self._handle_error("get device status", analyzer_id, e)

    # ==================== Log operations ====================

    def search_logs(
        self,
        analyzer_id: str,
        log_type: str = "traffic",
        filter_expr: Optional[str] = None,
        time_range: Optional[str] = None,
        limit: int = 100,
        device: Optional[str] = None,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Search logs with filters.

        Args:
            analyzer_id: Analyzer identifier
            log_type: Log type (traffic, event, security, app-ctrl, webfilter, etc.)
            filter_expr: Filter expression (e.g., "srcip=10.0.0.1 dstport=443")
            time_range: Time range (e.g., "1h", "24h", "7d", "30d")
            limit: Maximum number of results (default 100)
            device: Filter by device name
            adom: Administrative Domain

        Returns:
            List of Content objects with search results
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            result = faz.search_logs(
                adom=adom,
                log_type=log_type,
                filter_expr=filter_expr,
                time_range=time_range,
                limit=limit,
                device=device
            )
            return self._format_response(result, f"Log Search Results ({log_type})")
        except Exception as e:
            return self._handle_error("search logs", analyzer_id, e)

    def get_log_stats(
        self,
        analyzer_id: str,
        time_range: Optional[str] = None,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get log statistics and volume metrics.

        Args:
            analyzer_id: Analyzer identifier
            time_range: Time range for stats
            adom: Administrative Domain

        Returns:
            List of Content objects with log statistics
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            stats = faz.get_log_stats(adom=adom, time_range=time_range)
            return self._format_response(stats, "Log Statistics")
        except Exception as e:
            return self._handle_error("get log stats", analyzer_id, e)

    def get_log_fields(
        self,
        analyzer_id: str,
        log_type: str = "traffic",
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get available log fields for a log type.

        Args:
            analyzer_id: Analyzer identifier
            log_type: Log type
            adom: Administrative Domain

        Returns:
            List of Content objects with available fields
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            fields = faz.get_log_fields(adom=adom, log_type=log_type)
            return self._format_response(fields, f"Log Fields ({log_type})")
        except Exception as e:
            return self._handle_error("get log fields", analyzer_id, e)

    def get_raw_logs(
        self,
        analyzer_id: str,
        log_type: str = "traffic",
        time_range: Optional[str] = None,
        limit: int = 100,
        device: Optional[str] = None,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get raw log data.

        Args:
            analyzer_id: Analyzer identifier
            log_type: Log type
            time_range: Time range (e.g., "1h", "24h", "7d")
            limit: Maximum results
            device: Filter by device
            adom: Administrative Domain

        Returns:
            List of Content objects with raw logs
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            logs = faz.get_raw_logs(
                adom=adom,
                log_type=log_type,
                limit=limit,
                device=device
            )
            return self._format_response(logs, f"Raw Logs ({log_type})")
        except Exception as e:
            return self._handle_error("get raw logs", analyzer_id, e)

    # ==================== Report operations ====================

    def list_reports(self, analyzer_id: str, adom: Optional[str] = None) -> List[Content]:
        """List available report templates.

        Args:
            analyzer_id: Analyzer identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with report templates
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            reports = faz.list_reports(adom)
            return self._format_response(reports, "Report Templates")
        except Exception as e:
            return self._handle_error("list reports", analyzer_id, e)

    def run_report(
        self,
        analyzer_id: str,
        report_name: str,
        time_range: Optional[str] = None,
        devices: Optional[str] = None,
        output_format: str = "pdf",
        adom: Optional[str] = None
    ) -> List[Content]:
        """Run a report.

        Args:
            analyzer_id: Analyzer identifier
            report_name: Report template name
            time_range: Time range for report data
            devices: Comma-separated list of devices
            output_format: Output format (pdf, html, csv)
            adom: Administrative Domain

        Returns:
            List of Content objects with task ID
        """
        try:
            faz = self._get_analyzer(analyzer_id)

            # Parse devices if provided
            device_list = None
            if devices:
                device_list = [d.strip() for d in devices.split(",")]

            result = faz.run_report(
                report_name=report_name,
                adom=adom,
                devices=device_list,
                time_range=time_range,
                output_format=output_format
            )
            return self._format_response(result, f"Report Started: {report_name}")
        except Exception as e:
            return self._handle_error("run report", analyzer_id, e)

    def get_report_status(
        self,
        analyzer_id: str,
        task_id: int,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get report generation status.

        Args:
            analyzer_id: Analyzer identifier
            task_id: Report task ID
            adom: Administrative Domain

        Returns:
            List of Content objects with report status
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            status = faz.get_report_status(task_id, adom)
            return self._format_response(status, f"Report Status: {task_id}")
        except Exception as e:
            return self._handle_error("get report status", analyzer_id, e)

    def download_report(
        self,
        analyzer_id: str,
        task_id: int,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Download completed report.

        Args:
            analyzer_id: Analyzer identifier
            task_id: Report task ID
            adom: Administrative Domain

        Returns:
            List of Content objects with download URL or content
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            result = faz.download_report(task_id, adom)
            return self._format_response(result, f"Report Download: {task_id}")
        except Exception as e:
            return self._handle_error("download report", analyzer_id, e)

    # ==================== FortiView analytics ====================

    def get_fortiview(
        self,
        analyzer_id: str,
        view_type: str,
        time_range: Optional[str] = None,
        filter_expr: Optional[str] = None,
        limit: int = 20,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get FortiView dashboard data.

        Args:
            analyzer_id: Analyzer identifier
            view_type: View type (traffic, threat, application, source, destination, etc.)
            time_range: Time range
            filter_expr: Filter expression
            limit: Maximum results
            adom: Administrative Domain

        Returns:
            List of Content objects with FortiView data
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            data = faz.get_fortiview_data(
                view_type=view_type,
                adom=adom,
                time_range=time_range,
                filter_expr=filter_expr,
                limit=limit
            )
            return self._format_response(data, f"FortiView: {view_type}")
        except Exception as e:
            return self._handle_error("get fortiview", analyzer_id, e)

    def get_threat_stats(
        self,
        analyzer_id: str,
        time_range: Optional[str] = None,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get threat statistics and trends.

        Args:
            analyzer_id: Analyzer identifier
            time_range: Time range
            adom: Administrative Domain

        Returns:
            List of Content objects with threat statistics
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            stats = faz.get_threat_stats(adom=adom, time_range=time_range)
            return self._format_response(stats, "Threat Statistics")
        except Exception as e:
            return self._handle_error("get threat stats", analyzer_id, e)

    def get_top_sources(
        self,
        analyzer_id: str,
        time_range: Optional[str] = None,
        limit: int = 20,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get top traffic sources.

        Args:
            analyzer_id: Analyzer identifier
            time_range: Time range
            limit: Number of top sources
            adom: Administrative Domain

        Returns:
            List of Content objects with top sources
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            data = faz.get_top_sources(adom=adom, time_range=time_range, limit=limit)
            return self._format_response(data, "Top Sources")
        except Exception as e:
            return self._handle_error("get top sources", analyzer_id, e)

    def get_top_destinations(
        self,
        analyzer_id: str,
        time_range: Optional[str] = None,
        limit: int = 20,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get top traffic destinations.

        Args:
            analyzer_id: Analyzer identifier
            time_range: Time range
            limit: Number of top destinations
            adom: Administrative Domain

        Returns:
            List of Content objects with top destinations
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            data = faz.get_top_destinations(adom=adom, time_range=time_range, limit=limit)
            return self._format_response(data, "Top Destinations")
        except Exception as e:
            return self._handle_error("get top destinations", analyzer_id, e)

    def get_top_applications(
        self,
        analyzer_id: str,
        time_range: Optional[str] = None,
        limit: int = 20,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get top applications by traffic.

        Args:
            analyzer_id: Analyzer identifier
            time_range: Time range
            limit: Number of top applications
            adom: Administrative Domain

        Returns:
            List of Content objects with top applications
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            data = faz.get_top_applications(adom=adom, time_range=time_range, limit=limit)
            return self._format_response(data, "Top Applications")
        except Exception as e:
            return self._handle_error("get top applications", analyzer_id, e)

    # ==================== Event management ====================

    def get_event_summary(
        self,
        analyzer_id: str,
        time_range: Optional[str] = None,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get event summary and counts.

        Args:
            analyzer_id: Analyzer identifier
            time_range: Time range
            adom: Administrative Domain

        Returns:
            List of Content objects with event summary
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            summary = faz.get_event_summary(adom=adom, time_range=time_range)
            return self._format_response(summary, "Event Summary")
        except Exception as e:
            return self._handle_error("get event summary", analyzer_id, e)

    def list_alerts(
        self,
        analyzer_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        adom: Optional[str] = None
    ) -> List[Content]:
        """List active alerts.

        Args:
            analyzer_id: Analyzer identifier
            severity: Filter by severity (critical, high, medium, low)
            status: Filter by status (unread, read, acknowledged)
            limit: Maximum alerts to return
            adom: Administrative Domain

        Returns:
            List of Content objects with alerts
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            alerts = faz.list_alerts(
                adom=adom,
                severity=severity,
                status=status,
                limit=limit
            )
            return self._format_response(alerts, "Alerts")
        except Exception as e:
            return self._handle_error("list alerts", analyzer_id, e)

    def acknowledge_alert(
        self,
        analyzer_id: str,
        alert_id: str,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Acknowledge an alert.

        Args:
            analyzer_id: Analyzer identifier
            alert_id: Alert ID
            adom: Administrative Domain

        Returns:
            List of Content objects with result
        """
        try:
            faz = self._get_analyzer(analyzer_id)
            result = faz.acknowledge_alert(alert_id, adom)
            return self._format_response(result, f"Alert Acknowledged: {alert_id}")
        except Exception as e:
            return self._handle_error("acknowledge alert", analyzer_id, e)

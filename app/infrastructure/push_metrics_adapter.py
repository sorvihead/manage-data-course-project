import logging.config

from influxdb import InfluxDBClient

from config import Config

logger = logging.getLogger(__name__)


class InfluxPushMetricsAdapter:
    def __init__(self):
        self._client = None

    @property
    def client(self):
        if not self._client:
            try:
                self._client = InfluxDBClient(
                    host=Config.INFLUXDB_HOST, timeout=Config.INFLUXDB_TIMEOUT, database=Config.INFLUXDB_DATABASE,
                )
                self._client.query("show measurements")
            except Exception:
                logger.exception("Can't connect to InfluxDB")
        return self._client

    def push_metrics(self, data):
        """
        Push metrics to InfluxDb
        :param data: list of metrics
        :return:
        """
        json_bodies = list(map(self._get_normalized_json_body, data))
        try:
            if self.client and json_bodies:
                self.client.write_points(json_bodies)
        except Exception:
            logger.exception("Can't push metrics to InfluxDB")

    @staticmethod
    def _get_normalized_json_body(metrics):
        normalized_data = {
            "time": metrics["ts"] * (10 ** 9),
        }
        if metrics["measurement"] == "http_response_status":
            normalized_data["measurement"] = "http_response_status"
            normalized_data["tags"] = {
                "endpoint": metrics["endpoint"],
                "service": "verbalist",
                "status": metrics["metrics"]["status_code"],
            }
            normalized_data["fields"] = {
                "value": 1,
                "status_code": metrics["metrics"]["status_code"],
            }
        elif metrics["measurement"] == "http_response_time":
            normalized_data["measurement"] = "http_response_time"
            normalized_data["tags"] = {
                "endpoint": metrics["endpoint"],
                "service": "verbalist",
            }
            normalized_data["fields"] = {
                "value": metrics["metrics"]["elapsed_time"],
            }
        return normalized_data

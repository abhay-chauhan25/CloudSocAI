"""Stubbed boto3 clients for tests: no credentials, no network, unexpected calls fail."""

from collections.abc import Iterator
from contextlib import contextmanager

import boto3
from botocore import UNSIGNED
from botocore.client import BaseClient
from botocore.config import Config
from botocore.stub import Stubber


def unsigned_client(service: str, region: str = "us-east-1") -> BaseClient:
    return boto3.Session(region_name=region).client(
        service, config=Config(signature_version=UNSIGNED)
    )


class StubbedSession:
    """Stands in for boto3.Session: hands out one stubbed client per service.

    Use as a context manager; on exit it checks every queued response was used.
    """

    def __init__(self, *services: str) -> None:
        self.clients = {service: unsigned_client(service) for service in services}
        self.stubs = {service: Stubber(client) for service, client in self.clients.items()}

    def client(self, service: str, region_name: str | None = None) -> BaseClient:
        return self.clients[service]

    @contextmanager
    def active(self) -> Iterator["StubbedSession"]:
        for stub in self.stubs.values():
            stub.activate()
        try:
            yield self
            for stub in self.stubs.values():
                stub.assert_no_pending_responses()
        finally:
            for stub in self.stubs.values():
                stub.deactivate()

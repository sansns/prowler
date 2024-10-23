from typing import Optional

from botocore.exceptions import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class DirectConnect(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.connections = {}
        self.vifs = {}
        self.vgws = {}
        self.dxgws = {}
        self.__threading_call__(self._describe_connections)
        self.__threading_call__(self._describe_vifs)

    def _describe_connections(self, regional_client):
        """List DirectConnect(s) in the given region.

        Args:
            regional_client: The regional AWS client.
        """

        try:
            logger.info("DirectConnect - Listing Connections...")
            dx_connect = regional_client.describe_connections()

            for connection in dx_connect["connections"]:
                if not self.audit_resources or (
                    is_resource_filtered(
                        connection["connectionId"], self.audit_resources
                    )
                ):
                    connection_id = connection.get("connectionId")
                    self.connections[connection_id] = Connection(
                        id=connection_id,
                        name=connection["connectionName"],
                        location=connection["location"],
                        region=regional_client.region,
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_vifs(self, regional_client):
        """Describe each DirectConnect VIFs."""

        logger.info("DirectConnect - Describing VIFs...")
        try:
            describe_vifs = regional_client.describe_virtual_interfaces()
            for vif in describe_vifs["virtualInterfaces"]:
                if not self.audit_resources or (
                    is_resource_filtered(
                        vif["virtualInterfaceId"], self.audit_resources
                    )
                ):
                    vif_id = vif.get("virtualInterfaceId")
                    self.vifs[vif_id] = VirtualInterface(
                        id=vif_id,
                        name=vif["virtualInterfaceName"],
                        connection_id=vif["connectionId"],
                        vgw_gateway_id=vif["virtualGatewayId"],
                        dx_gateway_id=vif["directConnectGatewayId"],
                        location=vif["location"],
                        region=regional_client.region,
                    )
                    if vif[vif_id].vgw_gateway_id != "":
                        if vif[vif_id] in self.vgws:
                            self.vgws[vif["virtualGatewayId"]]["vifs"].append(
                                vif["virtualInterfaceId"]
                            )
                            self.vgws[vif["virtualGatewayId"]]["connections"].append(
                                vif["connectionId"]
                            )
                        else:
                            self.vgws[vif["virtualGatewayId"]] = VirtualGateway(
                                id=[vif["virtualGatewayId"]],
                                vifs=[vif["virtualInterfaceId"]],
                                connections=[vif["connectionId"]],
                                region=[vif["region"]],
                            )
                    if vif[vif_id].dx_gateway_id != "":
                        if vif[vif_id] in self.dxgws:
                            self.dxgws[vif["directConnectGatewayId"]]["vifs"].append(
                                vif["virtualInterfaceId"]
                            )
                            self.dxgws[vif["directConnectGatewayId"]][
                                "connections"
                            ].append(vif["connectionId"])
                        else:
                            self.dxgws[vif["directConnectGatewayId"]] = DXGateway(
                                id=[vif["directConnectGatewayId"]],
                                vifs=[vif["virtualInterfaceId"]],
                                connections=[vif["connectionId"]],
                                region=[vif["region"]],
                            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Connection(BaseModel):
    id: str
    name: Optional[str] = None
    location: str
    region: str


class VirtualInterface(BaseModel):
    id: str
    name: str
    connection_id: Optional[str] = None
    vgw_gateway_id: str
    dx_gateway_id: str
    location: str
    region: str


class VirtualGateway(BaseModel):
    id: str
    vifs: list
    connections: list
    region: str


class DXGateway(BaseModel):
    id: str
    vifs: list
    connections: list
    region: str

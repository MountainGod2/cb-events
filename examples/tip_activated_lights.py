# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cb-events ==7.0.1",
#     "aiohue ==4.8.1",
#     "python-dotenv >=1.2.2",
#     "rich-click >=1.9.7",
# ]
# ///

"""Tip-activated Philips Hue lights using cb-events and aiohue."""

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass, field
from typing import ClassVar

import rich_click as click
from aiohue import create_app_key
from aiohue.discovery import discover_nupnp
from aiohue.errors import AiohueException
from aiohue.v2 import HueBridgeV2
from dotenv import load_dotenv, set_key
from rich.logging import RichHandler

from cb_events import AuthError, ClientConfig, EventClient, EventType, Router
from cb_events.models import Event

click.rich_click.MAX_WIDTH = 100


@dataclass(frozen=True)
class HueConfig:
    """Configuration constants for Hue light control."""

    DEFAULT_HUE_IP: ClassVar[str] = "192.168.0.23"
    DEFAULT_HUE_APP_KEY: ClassVar[str] = ""
    FLASH_DELAY: ClassVar[float] = 0.5
    DEFAULT_REQUIRED_TOKENS: ClassVar[int] = 35
    COLOR_TIMEOUT: ClassVar[float] = 600.0
    DEFAULT_BRIGHTNESS: ClassVar[float] = 100.0

    COLOR_COMMANDS: ClassVar[dict[str, tuple[float, float]]] = {
        "red": (0.6750, 0.3220),
        "orange": (0.6000, 0.3600),
        "yellow": (0.5000, 0.4000),
        "green": (0.2151, 0.7106),
        "blue": (0.1538, 0.0600),
        "indigo": (0.2000, 0.1000),
        "violet": (0.2651, 0.1241),
        "white": (0.3227, 0.3290),
    }


@dataclass
class LightConfig:
    """Configuration for light effects."""

    brightness: float = HueConfig.DEFAULT_BRIGHTNESS
    transition_time: int = 1
    num_flashes: int = 3
    lights: list[str] = field(default_factory=list)
    color_timeout: float = HueConfig.COLOR_TIMEOUT


def setup_logging() -> None:
    """Configure logging with RichHandler."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[
            RichHandler(rich_tracebacks=True, tracebacks_show_locals=True)
        ],
    )
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("aiohue").setLevel(logging.WARNING)


load_dotenv()

logger = logging.getLogger("hue_light_control")

_LightState = tuple[bool, float | None, tuple[float, float] | None]


class HueController:
    """Manages Philips Hue lights via aiohue v2."""

    def __init__(
        self, bridge: HueBridgeV2, config: LightConfig | None = None
    ) -> None:
        """Initialize with a connected bridge and optional light config."""
        self.bridge = bridge
        self.config = config or LightConfig()
        self._light_ids: list[str] = self._get_light_ids()
        self._color_timer: asyncio.Task[None] | None = None

        logger.info("Found %d matching lights", len(self._light_ids))
        if not self._light_ids:
            logger.warning("No matching lights found on the Hue Bridge!")

    def _get_light_ids(self) -> list[str]:
        """Return IDs of lights matching config, or all lights."""
        return [
            light.id
            for light in self.bridge.lights
            if not self.config.lights
            or light.metadata.name in self.config.lights
        ]

    def _save_states(self) -> dict[str, _LightState]:
        """Capture current state of managed lights.

        Returns:
            A mapping of light ID to a tuple of (on, brightness, color_xy).
        """
        saved: dict[str, _LightState] = {}
        for light in self.bridge.lights:
            if light.id not in self._light_ids:
                continue
            on = light.on.on if light.on else False
            bri = light.dimming.brightness if light.dimming else None
            xy = (
                (light.color.xy.x, light.color.xy.y)
                if light.color and light.color.xy
                else None
            )
            saved[light.id] = (on, bri, xy)
        return saved

    async def _restore_single_state(
        self, light_id: str, state: _LightState
    ) -> None:
        on, bri, xy = state
        try:
            await self.bridge.lights.set_state(
                light_id, on=on, brightness=bri, color_xy=xy
            )
        except AiohueException:
            logger.warning("Failed to restore state for light %s", light_id)

    async def _restore_states(
        self, saved: dict[str, _LightState], *, delay: float = 0.0
    ) -> None:
        """Restore previously saved light states after an optional delay."""
        if delay:
            await asyncio.sleep(delay)
        for light_id, state in saved.items():
            await self._restore_single_state(light_id, state)
        logger.info("Reverted lights to original state")

    async def set_color(self, color: str) -> None:
        """Set all managed lights to a named color, reverting after timeout."""
        xy = HueConfig.COLOR_COMMANDS.get(color.strip().lower())
        if not xy:
            logger.warning("Unknown color: %s", color)
            return
        if not self._light_ids:
            logger.warning("No lights available")
            return

        if self._color_timer:
            self._color_timer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._color_timer

        saved = self._save_states()
        for light_id in self._light_ids:
            await self._set_single_light_color(light_id, xy)
        logger.info("Lights set to %s", color)

        self._color_timer = asyncio.create_task(
            self._restore_states(saved, delay=self.config.color_timeout)
        )

    async def _set_single_light_color(
        self, light_id: str, xy: tuple[float, float]
    ) -> None:
        try:
            await self.bridge.lights.set_state(
                light_id,
                on=True,
                brightness=self.config.brightness,
                color_xy=xy,
                transition_time=self.config.transition_time,
            )
        except AiohueException:
            logger.warning(
                "Bridge communication issue setting color on light %s",
                light_id,
            )

    async def flash_lights(self, color: str, count: int | None = None) -> None:
        """Flash managed lights in a named color."""
        xy = HueConfig.COLOR_COMMANDS.get(color.strip().lower())
        if not xy:
            logger.warning("Unknown color for flash: %s", color)
            return
        if not self._light_ids:
            logger.warning("No lights available to flash")
            return

        flashes = count or self.config.num_flashes
        saved = self._save_states()
        try:
            for _ in range(flashes):
                for light_id in self._light_ids:
                    await self._flash_single_light_on(light_id, xy)
                await asyncio.sleep(HueConfig.FLASH_DELAY)
                for light_id in self._light_ids:
                    await self._flash_single_light_off(light_id)
                await asyncio.sleep(HueConfig.FLASH_DELAY)
        finally:
            await self._restore_states(saved)

    async def _flash_single_light_on(
        self, light_id: str, xy: tuple[float, float]
    ) -> None:
        try:
            await self.bridge.lights.set_state(
                light_id,
                on=True,
                brightness=self.config.brightness,
                color_xy=xy,
                transition_time=0,
            )
        except AiohueException:
            logger.warning(
                "Bridge communication issue flashing light %s",
                light_id,
            )

    async def _flash_single_light_off(self, light_id: str) -> None:
        try:
            await self.bridge.lights.turn_off(light_id)
        except AiohueException:
            logger.warning(
                "Bridge communication issue turning off light %s",
                light_id,
            )


async def main(*, testbed: bool) -> None:
    """Main async entry point.

    Args:
        testbed: Whether to use the Chaturbate testbed environment.

    Raises:
        ValueError: If required environment variables are missing.
    """
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")
    if not username or not token:
        msg = "CB_USERNAME and CB_TOKEN must be set"
        raise ValueError(msg)

    hue_ip = os.getenv("HUE_IP", HueConfig.DEFAULT_HUE_IP)
    hue_app_key = os.getenv("HUE_APP_KEY", HueConfig.DEFAULT_HUE_APP_KEY)
    tip_threshold = int(
        os.getenv("TIP_THRESHOLD") or HueConfig.DEFAULT_REQUIRED_TOKENS
    )

    light_config = LightConfig()
    if raw_lights := os.getenv("LIGHT_NAMES"):
        light_config.lights = [
            n.strip() for n in raw_lights.split(",") if n.strip()
        ]
    if (raw_bri := os.getenv("BRIGHTNESS", "")) and raw_bri.replace(
        ".", "", 1
    ).isdigit():
        light_config.brightness = float(raw_bri)
    if (raw_timeout := os.getenv("COLOR_TIMEOUT", "")) and raw_timeout.replace(
        ".", "", 1
    ).isdigit():
        light_config.color_timeout = float(raw_timeout)

    logger.info("Hue Bridge IP: %s", hue_ip)
    logger.info(
        "Light targets: %s",
        ", ".join(light_config.lights) if light_config.lights else "all",
    )

    router = Router()
    config = ClientConfig(use_testbed=testbed)

    async with HueBridgeV2(hue_ip, hue_app_key) as bridge:
        hue = HueController(bridge, config=light_config)

        @router.on(EventType.TIP)
        async def handle_tip(event: Event) -> None:
            if (
                not event.tip
                or event.tip.tokens < tip_threshold
                or not event.tip.message
            ):
                return
            message = event.tip.message.lower()
            for color in HueConfig.COLOR_COMMANDS:
                if color in message.split():
                    await hue.set_color(color)
                    break

        async with EventClient(username, token, config=config) as client:
            async for event in client:
                await router.dispatch(event)


@click.group()
def cli() -> None:
    """Control Philips Hue lights based on Chaturbate tips."""


@cli.command()
@click.option("--testbed", is_flag=True, help="Use Chaturbate testbed")
def run(*, testbed: bool) -> None:
    """Start monitoring tips and activating lights."""
    setup_logging()
    try:
        asyncio.run(main(testbed=testbed))
    except AuthError:
        logger.exception(
            "Authentication failed. Check CB_USERNAME and CB_TOKEN."
        )
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception:
        logger.exception("Fatal error occurred")
    finally:
        logger.info("Hue Light Control script terminated")


@cli.command()
@click.option(
    "--host",
    default=None,
    help="Hue bridge IP or hostname (defaults to HUE_IP env var or auto-discovery).",  # noqa: E501
)
@click.option(
    "--env-file",
    default=".env",
    show_default=True,
    help=".env file to write HUE_APP_KEY into.",
)
def register(host: str | None, env_file: str) -> None:
    """Register this app with the Hue bridge and save the app key."""
    setup_logging()

    async def _register() -> None:
        bridge_host = host or os.getenv("HUE_IP")
        if not bridge_host:
            logger.info("No host provided; running bridge discovery...")
            bridges = await discover_nupnp()
            if not bridges:
                msg = "No Hue bridges found on the network."
                raise RuntimeError(msg)
            bridge_host = bridges[0].host
            logger.info("Discovered bridge at %s", bridge_host)

        click.echo(f"\nConnecting to bridge at {bridge_host}")
        click.echo("Press the LINK button on the bridge, then press Enter...")
        click.pause(info="")

        app_key = await create_app_key(bridge_host, "cb-events#tip-lights")
        set_key(env_file, "HUE_IP", bridge_host)
        set_key(env_file, "HUE_APP_KEY", app_key)
        click.echo(f"\nSuccess! App key saved to {env_file}")
        click.echo("Store this key safely — it does not expire.")

    try:
        asyncio.run(_register())
    except Exception:
        logger.exception("Registration failed")


@cli.command()
def discover() -> None:
    """Discover Hue bridges on the local network."""
    setup_logging()

    async def _discover() -> None:
        bridges = await discover_nupnp()
        if not bridges:
            click.echo("No Hue bridges found.")
            return
        click.echo(f"\nFound {len(bridges)} bridge(s):")
        for bridge in bridges:
            click.echo(f"  {bridge}")

    asyncio.run(_discover())


if __name__ == "__main__":
    cli()

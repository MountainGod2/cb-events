# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cb-events >=8.0.4",
#     "aiohue >=4.8.1",
#     "python-dotenv >=1.2.2",
#     "rich-click >=1.9.7",
# ]
# ///

"""CLI for setting up and managing tip-activated Philips Hue lights.

This script connects to the Chaturbate Events API to monitor for tip events,
and controls Philips Hue lights based on tip messages. It includes commands for
registering a new Hue app key and discovering bridges on the local network.

Usage:
    1. Set up environment variables (or use CLI options):
        - CB_USERNAME: Chaturbate username
        - CB_TOKEN: Chaturbate API token
        - HUE_IP: Hue bridge IP address (optional if using discovery)
        - HUE_APP_KEY: Hue app key (register with the 'register' command)
        - TIP_THRESHOLD: Minimum tokens for activating lights (default: 35)
        - LIGHT_NAMES: Comma-separated list of light names to control (default: all)
        - BRIGHTNESS: Brightness level for light effects (default: 100.0)
        - COLOR_TIMEOUT: Seconds before reverting color changes (default: 600.0)

    2. Register the app with the Hue bridge to get an app key:
        uv run examples/tip_activated_lights.py register

    3. Run the main script to start monitoring tips and controlling lights:
        uv run examples/tip_activated_lights.py run

    4. Optionally, discover Hue bridges on the local network:
        uv run examples/tip_activated_lights.py discover
"""  # noqa: E501

import asyncio
import contextlib
import logging
import os
import re
import signal
from dataclasses import dataclass, field
from typing import NamedTuple

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

logger = logging.getLogger("hue_light_control")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HUE_IP = "192.168.0.10"
DEFAULT_HUE_APP_KEY = ""
DEFAULT_TIP_THRESHOLD = 35
DEFAULT_BRIGHTNESS = 100.0
DEFAULT_COLOR_TIMEOUT = 600.0
FLASH_DELAY = 0.5

# CIE xy chromaticity coordinates for each named colour.
COLOR_XY: dict[str, tuple[float, float]] = {
    "red": (0.6750, 0.3220),
    "orange": (0.6000, 0.3600),
    "yellow": (0.5000, 0.4000),
    "green": (0.2151, 0.7106),
    "blue": (0.1538, 0.0600),
    "indigo": (0.2000, 0.1000),
    "violet": (0.2651, 0.1241),
    "white": (0.3227, 0.3290),
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class LightState(NamedTuple):
    """Snapshot of a single light's state."""

    on: bool
    brightness: float | None
    color_xy: tuple[float, float] | None


@dataclass
class LightConfig:
    """Runtime configuration for light effects."""

    brightness: float = DEFAULT_BRIGHTNESS
    transition_time: int = 1
    num_flashes: int = 3
    color_timeout: float = DEFAULT_COLOR_TIMEOUT
    # Empty list means "control all lights".
    lights: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _env_float(name: str, default: float) -> float:
    """Return *name* from the environment as a float, or *default*."""
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    """Return *name* from the environment as an int, or *default*."""
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _color_from_message(message: str) -> str | None:
    """Return the first known colour word found in *message*, or ``None``."""
    words = re.findall(r"\b\w+\b", message.lower())
    return next((word for word in words if word in COLOR_XY), None)


def _load_light_config() -> LightConfig:
    """Build a :class:`LightConfig` from the current environment.

    Returns:
        LightConfig: The loaded configuration.
    """
    lights = [
        name.strip()
        for name in os.getenv("LIGHT_NAMES", "").split(",")
        if name.strip()
    ]
    return LightConfig(
        brightness=_env_float("BRIGHTNESS", DEFAULT_BRIGHTNESS),
        color_timeout=_env_float("COLOR_TIMEOUT", DEFAULT_COLOR_TIMEOUT),
        lights=lights,
    )


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


class HueController:
    """Manages Philips Hue lights via *aiohue* v2.

    Original light states are captured once at construction time and are
    always the target when a colour-change timeout expires, regardless of
    how many intermediate colour changes have been requested.
    """

    def __init__(
        self, bridge: HueBridgeV2, config: LightConfig | None = None
    ) -> None:
        """Initialize the HueController with a bridge and optional config."""
        self.bridge = bridge
        self.config = config or LightConfig()
        self._light_ids: list[str] = self._resolve_light_ids()
        self._original_states: dict[str, LightState] = self._capture_states()
        self._color_timer: asyncio.Task[None] | None = None

        logger.info("Found %d matching light(s)", len(self._light_ids))
        if not self._light_ids:
            logger.warning("No matching lights found on the Hue bridge!")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_light_ids(self) -> list[str]:
        """Return IDs of lights matching the config, or all light IDs."""
        return [
            light.id
            for light in self.bridge.lights
            if not self.config.lights
            or light.metadata.name in self.config.lights  # ty:ignore[unresolved-attribute]
        ]

    def _capture_states(self) -> dict[str, LightState]:
        """Snapshot the current state of every managed light.

        Returns:
            A mapping of light ID to :class:`LightState` for every managed
            light.
        """
        states: dict[str, LightState] = {}
        for light in self.bridge.lights:
            if light.id not in self._light_ids:
                continue
            states[light.id] = LightState(
                on=light.on.on if light.on else False,
                brightness=light.dimming.brightness if light.dimming else None,
                color_xy=(
                    (light.color.xy.x, light.color.xy.y)
                    if light.color and light.color.xy
                    else None
                ),
            )
        return states

    async def _apply_state(self, light_id: str, state: LightState) -> None:
        """Push a previously captured :class:`LightState` back to *light_id*."""
        try:
            await self.bridge.lights.set_state(
                light_id,
                on=state.on,
                brightness=state.brightness,
                color_xy=state.color_xy,
            )
        except AiohueException:
            logger.warning("Failed to restore state for light %s", light_id)

    async def _restore_original_states(self, *, delay: float = 0.0) -> None:
        """Restore managed lights to startup state after *delay* seconds."""
        if delay:
            await asyncio.sleep(delay)
        for light_id, state in self._original_states.items():
            await self._apply_state(light_id, state)
        logger.info("Reverted lights to original state")

    async def _set_light_color(
        self, light_id: str, xy: tuple[float, float], *, transition_time: int
    ) -> None:
        try:
            await self.bridge.lights.set_state(
                light_id,
                on=True,
                brightness=self.config.brightness,
                color_xy=xy,
                transition_time=transition_time,
            )
        except AiohueException:
            logger.warning("Failed to set colour on light %s", light_id)

    async def _turn_off_light(self, light_id: str) -> None:
        try:
            await self.bridge.lights.turn_off(light_id)
        except AiohueException:
            logger.warning("Failed to turn off light %s", light_id)

    def _cancel_color_timer(self) -> asyncio.Task[None] | None:
        """Cancel any pending colour-revert timer and return it.

        Returns:
            The cancelled timer task, or ``None`` if there was no timer.
        """
        if self._color_timer and not self._color_timer.done():
            self._color_timer.cancel()
        return self._color_timer

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def set_color(self, color: str) -> None:
        """Set all managed lights to *color*, reverting after timeout.

        Any pending revert timer is cancelled and restarted so the timeout
        always counts from the most recent tip, and the target is always the
        original startup state — not whichever colour was active before
        this call.
        """
        xy = COLOR_XY.get(color.strip().lower())
        if not xy:
            logger.warning("Unknown colour: %s", color)
            return
        if not self._light_ids:
            logger.warning("No lights available")
            return

        if self._color_timer:
            self._color_timer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._color_timer

        for light_id in self._light_ids:
            await self._set_light_color(
                light_id, xy, transition_time=self.config.transition_time
            )
        logger.info("Lights set to %s", color)

        self._color_timer = asyncio.create_task(
            self._restore_original_states(delay=self.config.color_timeout)
        )

    async def flash_lights(self, color: str, count: int | None = None) -> None:
        """Flash managed lights in *color*, then restore original states."""
        xy = COLOR_XY.get(color.strip().lower())
        if not xy:
            logger.warning("Unknown colour for flash: %s", color)
            return
        if not self._light_ids:
            logger.warning("No lights available to flash")
            return

        flashes = count or self.config.num_flashes
        try:
            for _ in range(flashes):
                for light_id in self._light_ids:
                    await self._set_light_color(light_id, xy, transition_time=0)
                await asyncio.sleep(FLASH_DELAY)
                for light_id in self._light_ids:
                    await self._turn_off_light(light_id)
                await asyncio.sleep(FLASH_DELAY)
        finally:
            await self._restore_original_states()


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------


def _register_signal_handlers(task: asyncio.Task[object]) -> None:
    """Register SIGTERM/SIGINT to cancel *task*."""
    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, task.cancel)
    except NotImplementedError:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(
                sig, lambda _s, _f: loop.call_soon_threadsafe(task.cancel)
            )


async def run_app(*, testbed: bool) -> None:
    """Connect to the Hue bridge and start processing tip events.

    Args:
        testbed: Whether to use the Chaturbate testbed environment.

    Raises:
        RuntimeError: If called outside a running event loop task.
        ValueError: If ``CB_USERNAME`` or ``CB_TOKEN`` are not set.
    """
    username = os.getenv("CB_USERNAME")
    token = os.getenv("CB_TOKEN")
    if not username or not token:
        msg = "CB_USERNAME and CB_TOKEN must be set"
        raise ValueError(msg)

    hue_ip = os.getenv("HUE_IP", DEFAULT_HUE_IP)
    hue_app_key = os.getenv("HUE_APP_KEY", DEFAULT_HUE_APP_KEY)
    tip_threshold = _env_int("TIP_THRESHOLD", DEFAULT_TIP_THRESHOLD)
    light_config = _load_light_config()

    logger.info("Hue bridge IP: %s", hue_ip)
    logger.info(
        "Light targets: %s",
        ", ".join(light_config.lights) if light_config.lights else "all",
    )

    router = Router()
    client_config = ClientConfig(use_testbed=testbed)

    # Register cancellation signals so Ctrl-C / SIGTERM shuts down cleanly.
    current_task = asyncio.current_task()
    if current_task is None:
        msg = "run_app must be called from within a running event loop task"
        raise RuntimeError(msg)
    _register_signal_handlers(current_task)

    try:
        bridge = HueBridgeV2(hue_ip, hue_app_key)
        async with bridge:  # ty:ignore[invalid-context-manager]
            hue = HueController(bridge, config=light_config)

            @router.on(EventType.TIP)
            async def handle_tip(event: Event) -> None:
                if (
                    not event.tip
                    or event.tip.tokens < tip_threshold
                    or not event.tip.message
                ):
                    return
                color = _color_from_message(event.tip.message)
                if color:
                    await hue.set_color(color)

            async with EventClient(
                username, token, config=client_config
            ) as client:
                async for event in client:
                    await router.dispatch(event)
    except asyncio.CancelledError:
        logger.info("Shutting down")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.group()
def cli() -> None:
    """Control Philips Hue lights based on Chaturbate tips."""


@cli.command()
@click.option(
    "--testbed", is_flag=True, help="Use the Chaturbate testbed environment."
)
def run(*, testbed: bool) -> None:
    """Start monitoring tips and activating lights."""
    setup_logging()
    load_dotenv()
    try:
        asyncio.run(run_app(testbed=testbed))
    except AuthError:
        logger.exception(
            "Authentication failed — check CB_USERNAME and CB_TOKEN."
        )
    except Exception:
        logger.exception("Fatal error occurred")
    finally:
        logger.info("Hue light control terminated")


@cli.command()
@click.option(
    "--host",
    default=None,
    help=(
        "Hue bridge IP or hostname"
        " (defaults to HUE_IP env var or auto-discovery)."
    ),
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
    load_dotenv()

    async def _register() -> None:
        bridge_host = host or os.getenv("HUE_IP")
        if not bridge_host:
            logger.info("No host provided — running bridge discovery...")
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

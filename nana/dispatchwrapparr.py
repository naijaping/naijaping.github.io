#!/usr/bin/env python3

"""
Dispatchwrapparr - Version 0.4.4 Beta: A wrapper for Dispatcharr that supports the following:

  - M3U8/DASH-MPD best stream selection, segment download handling and piping to ffmpeg
  - DASH-MPD DRM clearkey support
  - HTTP Proxy Support
  - Support for Youtube Livestreams and many others
  - Extended MIME-type stream detection for Streamlink
  - URL header parameters support (#headers=origin&referer)
  - Enhanced Teletext/Subtitle support with FFmpeg

Usage: dispatchwrapper.py -i <URL> -ua <User Agent String>
Optional: -proxy <proxy server> -proxybypass <proxy bypass list> -clearkeys <file/url> -loglevel <level> -subtitles
"""

from __future__ import annotations

import os
import re
import sys
import signal
import itertools
import logging
import base64
import argparse
import requests
import socket
import ipaddress
import fnmatch
import json
from urllib.parse import urlparse, unquote

from collections import defaultdict
from contextlib import suppress
from typing import List, Self, Tuple, Optional, Dict
from datetime import timedelta

from streamlink import Streamlink
from streamlink.exceptions import PluginError, FatalPluginError, NoPluginError
from streamlink.plugin import Plugin, pluginmatcher, pluginargument
from streamlink.plugin.plugin import HIGH_PRIORITY, parse_params, stream_weight
from streamlink.stream.dash import DASHStream, DASHStreamWorker, DASHStreamWriter, DASHStreamReader
from streamlink.stream.dash.manifest import MPD, Representation
from streamlink.stream.ffmpegmux import FFMPEGMuxer
from streamlink.stream import HTTPStream, HLSStream, DASHStream
from streamlink.utils.url import update_scheme
from streamlink.session import Streamlink
from streamlink.utils.l10n import Language, Localization
from streamlink.utils.times import now

# Global variables
log = logging.getLogger("dispatchwrapparr")

"""
Begin DASH DRM Plugin
Code adapted from streamlink-plugin-dashdrm by titus-au: https://github.com/titus-au/streamlink-plugin-dashdrm
A special thanks!
"""

DASHDRM_OPTIONS = [
    "decryption-key",
    "presentation-delay",
    "use-subtitles",
]

@pluginmatcher(
    priority=HIGH_PRIORITY,
    pattern=re.compile(r"dashdrm://(?P<url>\S+)(?:\s(?P<params>.+))?$"),
)

@pluginargument(
    "decryption-key",
    type="comma_list",
    help="Decryption key to be passed to ffmpeg."
)

@pluginargument(
    "presentation-delay",
    help="Override presentation delay value (in seconds). Similar to"
    " --hls-live-edge."
)

@pluginargument(
    "use-subtitles",
    action="store_true",
    help="Enable subtitles"
)

class MPEGDASHDRM(Plugin):
    @classmethod
    def stream_weight(cls, stream):
        match = re.match(r"^(?:(.*)\+)?(?:a(\d+)k)$", stream)
        if match and match.group(1) and match.group(2):
            weight, group = stream_weight(match.group(1))
            weight += int(match.group(2))
            return weight, group
        elif match and match.group(2):
            return stream_weight(f"{match.group(2)}k")
        else:
            return stream_weight(stream)

    def _get_streams(self):
        data = self.match.groupdict()
        url = update_scheme("https://", data.get("url"), force=False)
        params = parse_params(data.get("params"))
        log.debug(f"URL={url}; params={params}")

        # process and store plugin options before passing streams back
        for option in DASHDRM_OPTIONS:
            if option == 'decryption-key':
                self.session.options[option] = self._process_keys()
            else:
                self.session.options[option] = self.get_option(option)

        return DASHStreamDRM.parse_manifest(self.session,
                                            url,
                                            **params)

    def _process_keys(self):
        keys = self.get_option('decryption-key')
        # if a colon separated key is given, assume its kid:key and take the
        # last component after the colon
        return_keys = []
        for k in keys:
            key = k.split(':')
            key_len = len(key[-1])
            log.debug('Decryption Key %s has %s digits', key[-1], key_len)
            if key_len in (21, 22, 23, 24):
                # key len of 21-24 may mean a base64 key was provided, so we
                # try and decode it
                log.debug("Decryption key length is too short to be hex and looks like it might be base64, so we'll try and decode it..")
                b64_string = key[-1]
                padding = 4 - (len(b64_string) % 4)
                b64_string = b64_string + ("=" * padding)
                b64_key = base64.urlsafe_b64decode(b64_string).hex()
                if b64_key:
                    key = [b64_key]
                    key_len = len(b64_key)
                    log.debug('Decryption Key (post base64 decode) is %s and has %s digits', key[-1], key_len)
            if key_len == 32:
                # sanity check that it's a valid hex string
                try:
                    int(key[-1], 16)
                except ValueError as err:
                    raise FatalPluginError(f"Expecting 128bit key in 32 hex digits, but the key contains invalid hex.")
            elif key_len != 32:
                raise FatalPluginError(f"Expecting 128bit key in 32 hex digits.")
            return_keys.append(key[-1])
        return return_keys


class FFMPEGMuxerDRM(FFMPEGMuxer):
    '''
    Inherit and extend the FFMPEGMuxer class to pass decryption keys
    to ffmpeg
    '''
    @classmethod
    def _get_keys(cls, session):
        keys=[]
        if session.options.get("decryption-key"):
            keys = session.options.get("decryption-key")
            if len(keys) == 1:
                keys.extend(keys)
        log.debug('Decryption Keys %s', keys)
        return keys

    def __init__(self, session, *streams, **options):
        super().__init__(session, *streams, **options)
        keys = self._get_keys(session)
        key = 0
        subtitles = self.session.options.get("use-subtitles")
        old_cmd = self._cmd.copy()
        self._cmd = []
        
        while len(old_cmd) > 0:
            cmd = old_cmd.pop(0)
            if keys and cmd == "-i":
                _ = old_cmd.pop(0)
                self._cmd.extend(["-re"])
                self._cmd.extend(["-readrate_initial_burst", "10"])
                self._cmd.extend(["-decryption_key", keys[key]])
                self._cmd.extend(["-copyts"])
                key += 1
                if key == len(keys):
                    key = 1
                self._cmd.extend([cmd, _])
            elif subtitles and cmd == "-c:a":
                _ = old_cmd.pop(0)
                self._cmd.extend([cmd, _])
                # Enhanced subtitle handling
                self._cmd.extend([
                    "-c:s", "copy",
                    "-f", "lavfi",
                    "-i", "anullsrc=channel_layout=stereo:sample_rate=44100",
                    "-metadata:s:s:0", "language=eng",
                    "-metadata:s:a:0", "language=eng"
                ])
            else:
                self._cmd.append(cmd)
        
        if self._cmd and (self._cmd[-1].startswith("pipe:") or not self._cmd[-1].startswith("-")):
            final_output = self._cmd.pop()
            self._cmd.extend(["-mpegts_copyts", "1"])
            self._cmd.extend(["-fflags", "+flush_packets"])
            self._cmd.extend(["-flush_packets", "1"])
            self._cmd.extend(["-max_delay", "50000"])
            self._cmd.append(final_output)
        log.debug("Updated ffmpeg command %s", self._cmd)

class DASHStreamWriterDRM(DASHStreamWriter):
    reader: DASHStreamReaderDRM
    stream: DASHStreamDRM


class DASHStreamWorkerDRM(DASHStreamWorker):
    reader: DASHStreamReaderDRM
    writer: DASHStreamWriterDRM
    stream: DASHStreamDRM

    def next_period_available(self):
        period_id = self.reader.ident[0]
        current_period_ids = [ p.id for p in self.mpd.periods ]
        current_period_idx = current_period_ids.index(period_id)

        log.debug("Current playing period: %s", current_period_idx + 1)
        log.debug("Number of periods: %s", len(current_period_ids))

        if len(current_period_ids) > current_period_idx + 1:
            return current_period_idx + 1
        return 0

    def check_new_rep(self):
        new_rep = None
        log.debug("Checking for new representations")
        next_period = self.next_period_available()
        if next_period:
            reloaded_streams = DASHStreamDRM.parse_manifest(self.session,
                                                        self.mpd.url,
                                                        next_period)
            reload_stream = reloaded_streams[self.stream.stream_name]
            if self.reader.mime_type == "video/mp4":
                new_rep = reload_stream.video_representation
                log.debug("New video representation found!")
            elif self.reader.mime_type == "audio/mp4":
                new_rep = reload_stream.audio_representation
                log.debug("New audio representation found!")
            else:
                log.debug("No new representation found!")
        return new_rep

    def iter_segments(self):
        init = True
        back_off_factor = 1
        new_rep = None
        yield_count = -1
        while not self.closed:
            representation = self.mpd.get_representation(self.reader.ident)

            if not new_rep:
                new_rep = self.check_new_rep()

            if self.mpd.type == "static":
                refresh_wait = 5
            else:
                refresh_wait = (
                    max(
                        self.mpd.minimumUpdatePeriod.total_seconds(),
                        min(representation.period.duration.total_seconds(),5)
                        if representation else 0,
                    )
                    or 5
                )

            if new_rep and not yield_count:
                self.reader.ident = new_rep.ident
                representation = new_rep
                new_rep = None
            elif new_rep and yield_count:
                refresh_wait = 1

            with self.sleeper(refresh_wait * back_off_factor):
                if not representation:
                    continue

                iter_segments = representation.segments(
                    init=init,
                    timestamp=self.reader.timestamp if init else None,
                )
                yield_count = 0
                for segment in iter_segments:
                    if self.closed:
                        break
                    yield_count += 1
                    yield segment

                if self.mpd.type != "dynamic":
                    self.close()
                    return

                if not self.reload():
                    back_off_factor = max(back_off_factor * 1.3, 10.0)
                else:
                    back_off_factor = 1

                init = False


class DASHStreamReaderDRM(DASHStreamReader):
    __worker__ = DASHStreamWorkerDRM
    __writer__ = DASHStreamWriterDRM

    worker: DASHStreamWorkerDRM
    writer: DASHStreamWriterDRM
    stream: DASHStreamDRM


class DASHStreamReaderSUB(DASHStreamReader):
    __worker__ = DASHStreamWorkerDRM
    __writer__ = DASHStreamWriterDRM

    worker: DASHStreamWorkerDRM
    writer: DASHStreamWriterDRM
    stream: DASHStreamDRM

    def read(self, size: int) -> bytes:
        _ = self.buffer.read(
            size,
            block=self.writer.is_alive(),
            timeout=self.timeout,
        )
        log.debug("Subtitle stream segment: %s", _)
        return _

class DASHStreamDRM(DASHStream):
    """
    Implementation of the "Dynamic Adaptive Streaming over HTTP" protocol (MPEG-DASH)
    """
    def __init__(
        self,
        session: Streamlink,
        mpd: MPD,
        video_representation: Representation | None = None,
        audio_representations: List[Representation] | None = None,
        subtitles_representations: List[Representation] | None = None,
        **kwargs,
    ):
        super().__init__(
            session,
            mpd,
            video_representation,
            audio_representations[0] if audio_representations[0] else None,
            **kwargs,
        )
        self.audio_representations = audio_representations
        self.subtitles_representations = subtitles_representations

    __shortname__ = "dashdrm"

    @classmethod
    def parse_manifest(
        cls,
        session: Streamlink,
        url_or_manifest: str,
        period: int | str = 0,
        with_video_only: bool = False,
        with_audio_only: bool = False,
        **kwargs,
    ) -> dict[str, DASHStreamDRM]:
        manifest, mpd_params = cls.fetch_manifest(session, url_or_manifest, **kwargs)

        try:
            mpd = cls.parse_mpd(manifest, mpd_params)
        except Exception as err:
            raise PluginError(f"Failed to parse MPD manifest: {err}") from err

        if session.options.get("presentation-delay"):
            presentation_delay = session.options.get("presentation-delay")
            mpd.suggestedPresentationDelay = timedelta(
                                                seconds=int(presentation_delay)
                                                )

        source = mpd_params.get("url", "MPD manifest")
        video: list[Representation | None] = [None] if with_audio_only else []
        audio: list[Representation | None] = [None] if with_video_only else []
        subtitles: list[Representation | None] = [None] if with_audio_only else []

        available_periods = [f"{idx}{f' (id={p.id!r})' if p.id is not None else ''}" for idx, p in enumerate(mpd.periods)]
        log.debug(f"Available DASH periods: {', '.join(available_periods)}")

        try:
            if isinstance(period, int):
                period_selection = mpd.periods[period]
            else:
                period_selection = mpd.periods_map[period]
        except LookupError:
            raise PluginError(
                f"DASH period {period!r} not found. Select a valid period by index or by id attribute value.",
            ) from None

        # Search for suitable video and audio representations
        for aset in period_selection.adaptationSets:
            if aset.contentProtections:
                if not session.options.get("decryption-key"):
                    raise PluginError(f"{source} is protected by DRM but no key given")
                else:
                    log.debug(f"{source} is protected by DRM")
            for rep in aset.representations:
                if rep.contentProtections:
                    if not session.options.get("decryption-key"):
                        raise PluginError(f"{source} is protected by DRM but no key given")
                    else:
                        log.debug(f"{source} is protected by DRM")
                if rep.mimeType.startswith("video"):
                    video.append(rep)
                elif rep.mimeType.startswith("audio"):  # pragma: no branch
                    audio.append(rep)
                elif (session.options.get("use-subtitles") and
                        (rep.mimeType.startswith("application") or 
                         rep.mimeType.startswith("text"))):
                    subtitles.append(rep)

        if not video:
            video.append(None)
        if not audio:
            audio.append(None)
        if not subtitles:
            subtitles.append(None)

        locale = session.localization
        locale_lang = locale.language
        lang = None
        available_languages = set()

        for aud in audio:
            if aud and aud.lang:
                available_languages.add(aud.lang)
                with suppress(LookupError):
                    if locale.explicit and aud.lang and Language.get(aud.lang) == locale_lang:
                        lang = aud.lang

        if not lang:
            lang = audio[0].lang if audio[0] else None

        log.debug(
            f"Available languages for DASH audio streams: {', '.join(available_languages) or 'NONE'} (using: {lang or 'n/a'})",
        )

        if len(available_languages) > 1:
            audio = [a for a in audio if a and (a.lang is None or a.lang == lang)]

        ret = []
        for vid, aud in itertools.product(video, audio):
            if not vid and not aud:
                continue

            stream = DASHStreamDRM(session, mpd, vid, audio, subtitles, **kwargs)
            stream_name = []

            if vid:
                stream_name.append(f"{vid.height or vid.bandwidth_rounded:0.0f}{'p' if vid.height else 'k'}")
            ret.append(("+".join(stream_name), stream))

        dict_value_list = defaultdict(list)
        for k, v in ret:
            dict_value_list[k].append(v)

        def sortby_bandwidth(dash_stream: DASHStreamDRM) -> float:
            if dash_stream.video_representation:
                return dash_stream.video_representation.bandwidth
            return 0

        ret_new = {}
        for q in dict_value_list:
            items = dict_value_list[q]

            with suppress(AttributeError):
                items = sorted(items, key=sortby_bandwidth, reverse=True)

            for n in range(len(items)):
                if n == 0:
                    ret_new[q] = items[n]
                elif n == 1:
                    ret_new[f"{q}_alt"] = items[n]
                else:
                    ret_new[f"{q}_alt{n}"] = items[n]

        for stream_name in ret_new:
            ret_new[stream_name].stream_name = stream_name

        return ret_new

    def open(self):
        video, audio, audio1 = None, None, None
        rep_video = self.video_representation
        rep_audios = self.audio_representations
        rep_subtitles = self.subtitles_representations

        timestamp = now()

        fds = []

        maps = ["0:v?", "0:a?"]
        metadata = {}

        if rep_video:
            video = DASHStreamReaderDRM(self, rep_video, timestamp)
            log.debug(f"Opening DASH reader for: {rep_video.ident!r} - {rep_video.mimeType}")
            video.open()
            fds.append(video)

        next_map = 1
        if rep_audios:
            for i, rep_audio in enumerate(rep_audios):
                audio = DASHStreamReaderDRM(self, rep_audio, timestamp)
                if not audio1:
                    audio1 = audio
                log.debug(f"Opening DASH reader for: {rep_audio.ident!r} - {rep_audio.mimeType}")
                audio.open()
                fds.append(audio)
                metadata["s:a:{0}".format(i)] = ["language={0}".format(rep_audio.lang), "title=\"{0}\"".format(rep_audio.lang)]
            maps.extend(f"{i}:a" for i in range(next_map, next_map + len(rep_audios)))
            next_map = len(rep_audios) + 1

        if rep_subtitles and rep_subtitles[0] and rep_video:
            for _, rep_subtitle in enumerate(rep_subtitles):
                subtitle = DASHStreamReaderSUB(self, rep_subtitle, timestamp)
                log.debug(f"Opening DASH reader for: {rep_subtitle.ident!r} - {rep_subtitle.mimeType}")
                subtitle.open()
                fds.append(subtitle)
                metadata["s:s:{0}".format(_)] = ["language={0}".format(rep_subtitle.lang), "title=\"{0}\"".format(rep_subtitle.lang)]
            maps.extend(f"{_}:s" for _ in range(next_map, next_map + len(rep_subtitles)))

        if video and audio and FFMPEGMuxerDRM.is_usable(self.session):
            return FFMPEGMuxerDRM(self.session, *fds, copyts=True, maps=maps, metadata=metadata).open()
        elif video:
            return video
        elif audio:
            return audio1

"""
End of DASHDRM Plugin Section
Beginning of Dispatchwrapparr Section
"""

def parse_args():
    parser = argparse.ArgumentParser(description="Dispatchwrapparr: A wrapper for Dispatcharr")
    parser.add_argument("-i", required=True, help="Input URL")
    parser.add_argument("-ua", required=True, help="User-Agent string")
    parser.add_argument("-proxy", help="Optional HTTP proxy (e.g. http://127.0.0.1:8888)")
    parser.add_argument("-proxybypass", help="Comma-separated list of hostnames or IP patterns to bypass the proxy (e.g. '192.168.*.*,*.lan')")
    parser.add_argument("-clearkeys", help="Optional Supply a json file or URL containing URL/Clearkey maps (e.g. 'clearkeys.json' or 'https://some.host/clearkeys.json')")
    parser.add_argument("-subtitles", action="store_true", help="Enable support for subtitles (if available)")
    parser.add_argument("-teletext", action="store_true", help="Enable support for teletext subtitles (if available)")
    parser.add_argument("-loglevel", type=str, default="INFO", choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"], help="Enable logging and set log level. (default: INFO)")
    args = parser.parse_args()

    if args.proxybypass and not args.proxy:
        parser.error("argument -proxybypass: requires -proxy to be set")

    return args


def configure_logging(level="INFO") -> logging.Logger:
    level = level.upper()
    numeric_level = getattr(logging, level, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    if not root_logger.handlers:
        formatter = logging.Formatter("[%(name)s] %(asctime)s [%(levelname)s] %(message)s")
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        root_logger.addHandler(console)

    streamlink_log = logging.getLogger("streamlink")
    streamlink_log.setLevel(numeric_level)
    streamlink_log.propagate = True

    log = logging.getLogger("dispatchwrapparr")
    return log

def parse_header_params(raw_url: str) -> Tuple[str, Dict[str, str]]:
    if '#headers=' not in raw_url:
        return raw_url, {}
    
    base_url, header_params = raw_url.split('#headers=', 1)
    headers = {}
    
    for param in header_params.split('&'):
        if ':' in param:
            key, value = param.split(':', 1)
            headers[key.lower()] = unquote(value)
    
    return base_url, headers

def check_clearkey_in_url(raw_url: str):
    headers = {}
    clearkey = None
    stream_url = raw_url
    
    if '#headers=' in raw_url:
        stream_url, headers = parse_header_params(raw_url)
        raw_url = stream_url
    
    if '#clearkey=' in raw_url:
        stream_url, clearkey = raw_url.split('#clearkey=', 1)
    
    return stream_url, clearkey, headers

def proxy_bypass_req(url: str, useragent: str, bypasslist: str, headers: Dict[str, str] = None) -> str | None:
    req_headers = {"User-Agent": useragent}
    if headers:
        req_headers.update(headers)
    proxies = {}
    bypass_patterns = [pattern.strip() for pattern in bypasslist.split(",")]

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname or not any(fnmatch.fnmatch(hostname, pat) for pat in bypass_patterns):
            return url

        while True:
            response = requests.get(url, headers=req_headers, proxies=proxies, allow_redirects=False, timeout=5)
            status = response.status_code
            if status == 200:
                return None
            elif status in (301, 302):
                location = response.headers.get("Location")
                if not location:
                    break
                next_host = urlparse(location).hostname
                if next_host and any(fnmatch.fnmatch(next_host, pat) for pat in bypass_patterns):
                    url = location
                    continue
                else:
                    return location
            else:
                return url
    except Exception as e:
        log.warning(f"proxy_bypass_req failed: {e}")
        return url

def check_clearkeys_for_url(stream_url: str, clearkeys_source: str = None) -> str | None:
    def is_url(path_or_url):
        parsed = urlparse(path_or_url)
        return parsed.scheme in ('http', 'https')

    def resolve_path(path: str) -> str:
        if os.path.isabs(path):
            return path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(script_dir, path)

    log.info(f"Clearkeys Source: '{clearkeys_source}'")

    try:
        log.info(f"Attempting to load json data from '{clearkeys_source}'")
        if is_url(clearkeys_source):
            response = requests.get(clearkeys_source, timeout=10)
            response.raise_for_status()
            keymap = response.json()
        else:
            resolved_file = resolve_path(clearkeys_source)
            with open(resolved_file, "r") as f:
                keymap = json.load(f)
    except Exception as e:
        log.error(f"Failed to load ClearKey JSON from '{clearkeys_source}': {e}")
        return None

    for pattern, clearkey in keymap.items():
        if fnmatch.fnmatch(stream_url, pattern):
            log.info(f"Clearkey(s) match for '{stream_url}': '{clearkey}'")
            return clearkey

    log.info(f"No matching clearkey(s) found for '{stream_url}'. Moving on.")
    return None

def detect_stream_type(session, url, user_agent=None, proxy=None, headers=None):
    try:
        if headers:
            session.set_option("http-headers", headers)
        return session.streams(url)
    except NoPluginError:
        log.warning("No plugin found for URL. Attempting fallback based on MIME type...")

        req_headers = {
            "User-Agent": user_agent or "Mozilla/5.0",
            "Range": "bytes=0-1023"
        }
        if headers:
            req_headers.update(headers)

        proxies = {
            "http": proxy,
            "https": proxy
        } if proxy else None

        try:
            response = requests.get(
                url,
                headers=req_headers,
                proxies=proxies,
                stream=True,
                timeout=5
            )
            content_type = response.headers.get("Content-Type", "").lower()
            log.info(f"Detected Content-Type: {content_type}")
        except Exception as e:
            log.error(f"Could not detect stream type: {e}")
            raise

        if "vnd.apple.mpegurl" in content_type or "x-mpegurl" in content_type:
            return HLSStream.parse_variant_playlist(session, url)
        elif "dash+xml" in content_type:
            return DASHStream.parse_manifest(session, url)
        elif "video/mp2t" in content_type or "application/octet-stream" in content_type:
            return {"live": HTTPStream(session, url)}
        else:
            log.error("Unrecognized Content-Type for fallback")
            raise

    except PluginError as e:
        log.error(f"Plugin failed: {e}")
        raise

def main():
    global log
    args = parse_args()
    log = configure_logging(args.loglevel)
    
    input_url, clearkey, url_headers = check_clearkey_in_url(args.i)
    
    log.info(f"Stream URL: '{input_url}'")
    if clearkey:
        log.info(f"Clearkey found in URL")
    if url_headers:
        log.info(f"Custom headers from URL: {url_headers}")
    log.info(f"User Agent: '{args.ua}'")
    if args.proxy:
        log.info(f"HTTP Proxy: '{args.proxy}'")

    if clearkey is None and args.clearkeys:
        clearkey = check_clearkeys_for_url(args.i, args.clearkeys)

    if args.proxybypass:
        log.info(f"Proxy Bypass: '{args.proxybypass}'")
        bypass_result = proxy_bypass_req(input_url, args.ua, args.proxybypass, url_headers)
        if bypass_result is None:
            log.info("Bypassing supplied proxy for stream URL: '{input_url}'")
            args.proxy = None
        else:
            input_url = bypass_result
            log.info(f"Determined stream URL to proxy: '{input_url}'")

    session = Streamlink()
    
    headers = {"User-Agent": args.ua}
    if url_headers:
        headers.update(url_headers)
    
    session.set_option("http-headers", headers)

    if args.proxy:
        session.set_option("http-proxy", args.proxy)

    # Enhanced subtitle/teletext handling
    if args.subtitles or args.teletext:
        log.info("Subtitle support enabled")
        session.set_option("mux-subtitles", True)
        session.set_option("subtitle-languages", "all")
        if args.teletext:
            log.info("Teletext support enabled")
            session.set_option("ffmpeg-options", "parse_teletext=1")

    python_loglevel = args.loglevel.upper()
    python_to_ffmpeg_loglevel = {
        "CRITICAL": "panic",
        "ERROR":    "error",
        "WARNING":  "warning",
        "INFO":     "info",
        "DEBUG":    "debug",
        "NOTSET":   "trace"
    }

    ffmpeg_loglevel = python_to_ffmpeg_loglevel.get(python_loglevel)
    session.set_option("ffmpeg-loglevel", ffmpeg_loglevel)
    session.set_option("ffmpeg-fout", "mpegts")
    session.set_option("ffmpeg-verbose", True)
    session.set_option("stream-segment-threads", 2)
    streams = None

    if clearkey:
        log.info(f"Clearkey(s): '{clearkey}'")
        input_url = f"dashdrm://{input_url}"
        plugin = MPEGDASHDRM(session, input_url)
        plugin.options["decryption-key"] = [clearkey]
        plugin.options["presentation-delay"] = 30
        if args.subtitles or args.teletext:
            plugin.options["use-subtitles"]
        try:
            streams = plugin.streams()
        except PluginError as e:
            log.error(f"Failed to load DRM plugin: {e}")
            return
    else:
        session.set_option("ffmpeg-copyts", True)
        session.set_option("hls-start-offset", 30)
        session.set_option("ffmpeg-start-at-zero", True)
        try:
            streams = detect_stream_type(session, input_url, user_agent=args.ua, proxy=args.proxy, headers=url_headers)
        except Exception as e:
            log.error(f"Stream setup failed: {e}")
            return

    if not streams:
        log.error("No playable streams found.")
        return

    log.info("Selecting best available stream.")
    stream = streams.get("best") or streams.get("live") or next(iter(streams.values()), None)

    if not stream:
        log.error("No streams available.")
        return

    try:
        log.info("Starting stream.")
        with stream.open() as fd:
            while True:
                data = fd.read(188 * 64)
                if not data:
                    break
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except BrokenPipeError:
                    break
    except KeyboardInterrupt:
        log.info("Stream interrupted, canceling.")

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

if __name__ == "__main__":
    main()

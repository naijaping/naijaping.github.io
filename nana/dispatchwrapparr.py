#!/usr/bin/env python3

"""
Dispatchwrapparr - Version 0.4.6 Beta: Complete subtitle/teletext solution
"""

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

class FFMPEGMuxerSubtitles(FFMPEGMuxer):
    def __init__(self, session, *streams, **options):
        super().__init__(session, *streams, **options)
        
        # Rebuild FFmpeg command with proper subtitle handling
        old_cmd = self._cmd.copy()
        self._cmd = []
        subtitle_index = 0
        audio_index = 0
        
        while len(old_cmd) > 0:
            cmd = old_cmd.pop(0)
            
            if cmd == "-i":
                input_file = old_cmd.pop(0)
                self._cmd.extend([cmd, input_file])
                
                # Detect subtitle streams
                if "subtitle" in input_file or "subtitles" in input_file:
                    self._cmd.extend([
                        "-map", f"0:s:{subtitle_index}",
                        "-c:s", "mov_text",
                        "-metadata:s:s:0", "language=eng"
                    ])
                    subtitle_index += 1
            
            elif cmd == "-c:a":
                codec = old_cmd.pop(0)
                self._cmd.extend([cmd, codec])
                
                # Add teletext parsing if enabled
                if session.options.get("teletext"):
                    self._cmd.extend([
                        "-parse_teletext", "1",
                        "-fix_sub_duration"
                    ])
            else:
                self._cmd.append(cmd)
        
        # Add global parameters
        self._cmd.extend([
            "-f", "mpegts",
            "-mpegts_flags", "+resend_headers",
            "-muxdelay", "0",
            "-flush_packets", "1"
        ])
        
        log.debug(f"Final FFmpeg command: {' '.join(self._cmd)}")

class DASHStreamReaderWithSubtitles(DASHStreamReader):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subtitle_tracks = []

    def detect_subtitles(self):
        if self.stream.subtitles_representations:
            for idx, rep in enumerate(self.stream.subtitles_representations):
                if rep.mimeType.startswith(("text", "application")):
                    self.subtitle_tracks.append({
                        "index": idx,
                        "lang": rep.lang or "und",
                        "type": "teletext" if "teletext" in rep.mimeType.lower() else "subtitle"
                    })

class DASHStreamWithSubtitles(DASHStream):
    def open(self):
        self.reader = DASHStreamReaderWithSubtitles(self, self.video_representation, now())
        self.reader.detect_subtitles()
        
        if self.session.options.get("subtitles") and self.reader.subtitle_tracks:
            log.info(f"Found {len(self.reader.subtitle_tracks)} subtitle tracks")
            for track in self.reader.subtitle_tracks:
                log.info(f"  - Track {track['index']}: {track['lang']} ({track['type']})")
        
        return FFMPEGMuxerSubtitles(
            self.session,
            self.reader,
            maps=["0:v?", "0:a?"],
            metadata={"title": "Dispatchwrapparr Stream"}
        ).open()

def parse_args():
    parser = argparse.ArgumentParser(description="Dispatchwrapparr with enhanced subtitle support")
    parser.add_argument("-i", required=True, help="Input URL")
    parser.add_argument("-ua", required=True, help="User-Agent string")
    parser.add_argument("-proxy", help="HTTP proxy server")
    parser.add_argument("-proxybypass", help="Proxy bypass list")
    parser.add_argument("-clearkeys", help="ClearKey DRM keys file/URL")
    parser.add_argument("-subtitles", action="store_true", help="Enable subtitles")
    parser.add_argument("-teletext", action="store_true", help="Enable teletext extraction")
    parser.add_argument("-loglevel", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Log level")
    return parser.parse_args()

def configure_logging(level):
    logging.basicConfig(
        level=level,
        format="[%(name)s] %(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger("dispatchwrapparr")

def main():
    args = parse_args()
    log = configure_logging(args.loglevel.upper())
    
    # Session setup
    session = Streamlink()
    session.set_option("http-headers", {"User-Agent": args.ua})
    
    if args.proxy:
        session.set_option("http-proxy", args.proxy)
    
    # Subtitle configuration
    if args.subtitles or args.teletext:
        session.set_option("mux-subtitles", True)
        session.set_option("subtitle-languages", "all")
        
        if args.teletext:
            session.set_option("teletext", True)
            log.info("Teletext extraction enabled")
    
    # Get streams
    try:
        streams = session.streams(args.i)
        if not streams:
            log.error("No streams found")
            return
        
        best_stream = streams.get("best")
        if not best_stream:
            log.error("No playable streams found")
            return
        
        log.info(f"Starting stream with {'subtitles' if args.subtitles else 'no subtitles'}")
        with best_stream.open() as stream:
            while True:
                data = stream.read(1024 * 188)  # Optimal TS packet size
                if not data:
                    break
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except BrokenPipeError:
                    break
    
    except Exception as e:
        log.error(f"Stream error: {e}")
        return

if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    main()

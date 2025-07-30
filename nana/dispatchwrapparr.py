#!/usr/bin/env python3

"""
Dispatchwrapparr - Version 0.4.5 Beta: Enhanced subtitle/teletext support
"""

[Previous imports and DASH DRM plugin code remain exactly the same until the FFMPEGMuxerDRM class]

class FFMPEGMuxerDRM(FFMPEGMuxer):
    def __init__(self, session, *streams, **options):
        super().__init__(session, *streams, **options)
        
        # Get keys if DRM is enabled
        keys = []
        if session.options.get("decryption-key"):
            keys = session.options.get("decryption-key")
            if len(keys) == 1:
                keys.extend(keys)
        
        # Enhanced subtitle handling
        subtitles_enabled = session.options.get("mux-subtitles")
        teletext_enabled = session.options.get("teletext")
        
        old_cmd = self._cmd.copy()
        self._cmd = []
        key_index = 0
        
        while len(old_cmd) > 0:
            cmd = old_cmd.pop(0)
            
            # Handle DRM decryption keys
            if keys and cmd == "-i":
                _ = old_cmd.pop(0)
                self._cmd.extend(["-re"])
                self._cmd.extend(["-decryption_key", keys[key_index]])
                key_index += 1
                if key_index == len(keys):
                    key_index = 1
                self._cmd.extend([cmd, _])
            
            # Enhanced subtitle/teletext handling
            elif subtitles_enabled and cmd == "-c:a":
                _ = old_cmd.pop(0)
                self._cmd.extend([cmd, _])
                
                # Add subtitle stream handling
                self._cmd.extend(["-c:s", "mov_text"])  # Use mov_text for better compatibility
                
                if teletext_enabled:
                    self._cmd.extend([
                        "-fix_sub_duration",
                        "-parse_teletext", "1"
                    ])
            
            else:
                self._cmd.append(cmd)
        
        # Final optimizations
        if self._cmd and (self._cmd[-1].startswith("pipe:") or not self._cmd[-1].startswith("-")):
            final_output = self._cmd.pop()
            self._cmd.extend([
                "-mpegts_copyts", "1",
                "-fflags", "+flush_packets",
                "-max_delay", "500000",  # Increased delay for better subtitle sync
                final_output
            ])
        
        log.debug(f"Final FFmpeg command: {' '.join(self._cmd)}")

[Rest of the DASH DRM plugin code remains the same]

def parse_args():
    parser = argparse.ArgumentParser(description="Dispatchwrapparr: A wrapper for Dispatcharr")
    parser.add_argument("-i", required=True, help="Input URL")
    parser.add_argument("-ua", required=True, help="User-Agent string")
    parser.add_argument("-proxy", help="Optional HTTP proxy")
    parser.add_argument("-proxybypass", help="Comma-separated list of hostnames or IP patterns to bypass the proxy")
    parser.add_argument("-clearkeys", help="Optional JSON file/URL containing URL/Clearkey maps")
    parser.add_argument("-subtitles", action="store_true", help="Enable support for subtitles")
    parser.add_argument("-teletext", action="store_true", help="Enable support for teletext subtitles")
    parser.add_argument("-loglevel", type=str, default="INFO", choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"], help="Log level")
    args = parser.parse_args()

    if args.proxybypass and not args.proxy:
        parser.error("argument -proxybypass: requires -proxy to be set")

    return args

def main():
    global log
    args = parse_args()
    log = configure_logging(args.loglevel)
    
    input_url, clearkey, url_headers = check_clearkey_in_url(args.i)
    
    log.info(f"Stream URL: '{input_url}'")
    if clearkey:
        log.info("Clearkey found in URL")
    if url_headers:
        log.info(f"Custom headers from URL: {url_headers}")

    session = Streamlink()
    
    # Set headers
    headers = {"User-Agent": args.ua}
    if url_headers:
        headers.update(url_headers)
    session.set_option("http-headers", headers)

    # Set proxy if configured
    if args.proxy:
        session.set_option("http-proxy", args.proxy)

    # Enhanced subtitle/teletext configuration
    if args.subtitles or args.teletext:
        session.set_option("mux-subtitles", True)
        session.set_option("subtitle-languages", "all")
        
        if args.teletext:
            session.set_option("teletext", True)
            session.set_option("ffmpeg-options", "parse_teletext=1:fix_sub_duration=1")
            log.info("Teletext support enabled with full parsing")
        
        log.info(f"Subtitle support enabled ({'teletext' if args.teletext else 'standard'})")

    # FFmpeg configuration
    session.set_option("ffmpeg-fout", "mpegts")
    session.set_option("ffmpeg-verbose", True)
    session.set_option("stream-segment-threads", 3)  # Increased for better performance

    # Get streams
    try:
        if clearkey:
            input_url = f"dashdrm://{input_url}"
            plugin = MPEGDASHDRM(session, input_url)
            plugin.options["decryption-key"] = [clearkey]
            streams = plugin.streams()
        else:
            streams = detect_stream_type(session, input_url, user_agent=args.ua, proxy=args.proxy, headers=url_headers)
    except Exception as e:
        log.error(f"Stream setup failed: {e}")
        return

    if not streams:
        log.error("No playable streams found")
        return

    # Select best stream
    stream = streams.get("best") or streams.get("live") or next(iter(streams.values()), None)
    if not stream:
        log.error("No streams available")
        return

    # Start streaming
    try:
        log.info("Starting stream with subtitle support")
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
        log.info("Stream interrupted")
    except Exception as e:
        log.error(f"Stream error: {e}")

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

if __name__ == "__main__":
    main()

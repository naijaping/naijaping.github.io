# app/routes.py
from flask import Flask, request, render_template, redirect, url_for, jsonify
from .models import ChannelManager
from .utils import is_stream_healthy, proxy_stream
import logging

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
channel_manager = ChannelManager()

@app.route('/')
def index():
    channels = channel_manager.list_channels()
    for key, ch in channels.items():
        ch['status'] = []
        for src in ch['sources']:
            if src.get('enabled', True):
                healthy = is_stream_healthy(src['url'])
                ch['status'].append(healthy)
            else:
                ch['status'].append(False)  # ← FIXED: 'status', not 'destaatus'
    return render_template('index.html', channels=channels)

@app.route('/<channel_key>')
def stream(channel_key):
    ch = channel_manager.get_channel(channel_key)
    if not ch:
        return "Channel not found", 404

    sources = [s for s in ch["sources"] if s.get("enabled", True)]
    if not sources:
        return "No enabled sources", 503

    # Try healthy sources first
    for src in sources:
        if is_stream_healthy(src["url"]):
            proxy_resp = proxy_stream(src["url"])
            if proxy_resp:
                return proxy_resp

    # Fallback: proxy first enabled source even if unhealthy
    proxy_resp = proxy_stream(sources[0]["url"])
    if proxy_resp:
        return proxy_resp

    return "All sources failed", 502

# Add this route BELOW your existing routes
@app.route('/health/<channel_key>')
def health_check(channel_key):
    ch = channel_manager.get_channel(channel_key)
    if not ch:
        return jsonify({"error": "Channel not found"}), 404

    enabled_sources = [s for s in ch["sources"] if s.get("enabled", True)]
    if not enabled_sources:
        return jsonify({"total": 0, "healthy": 0, "sources": []})

    results = []
    healthy_count = 0

    for src in enabled_sources:
        healthy = is_stream_healthy(src["url"])
        results.append({
            "url": src["url"],
            "healthy": healthy
        })
        if healthy:
            healthy_count += 1

    return jsonify({
        "total": len(enabled_sources),
        "healthy": healthy_count,
        "sources": results
    })

# --- Admin Routes (unchanged but validated) ---

@app.route('/admin/add', methods=['GET', 'POST'])
def add_channel():
    if request.method == 'POST':
        key = request.form['key'].strip()
        name = request.form['name'].strip()
        urls = [u.strip() for u in request.form.getlist('urls') if u.strip()]
        sources = [{"url": u, "enabled": True} for u in urls]
        if key and name and sources:
            channel_manager.add_channel(key, name, sources)
        return redirect(url_for('index'))
    return render_template('edit_channel.html', action='Add')

@app.route('/admin/edit/<key>', methods=['GET', 'POST'])
def edit_channel(key):
    ch = channel_manager.get_channel(key)
    if not ch:
        return "Channel not found", 404
    if request.method == 'POST':
        name = request.form['name'].strip()
        urls = [u.strip() for u in request.form.getlist('urls') if u.strip()]
        sources = [{"url": u, "enabled": True} for u in urls]
        if name and sources:
            channel_manager.update_channel(key, name, sources)
        return redirect(url_for('index'))
    return render_template('edit_channel.html', key=key, name=ch['name'], sources=ch['sources'], action='Edit')

@app.route('/admin/delete/<key>')
def delete_channel(key):
    channel_manager.delete_channel(key)
    return redirect(url_for('index'))

@app.route('/admin/move/<key>', methods=['POST'])
def move_source(key):
    idx_from = int(request.form['from'])
    idx_to = int(request.form['to'])
    channel_manager.move_source(key, idx_from, idx_to)
    return redirect(url_for('edit_channel', key=key))

@app.route('/admin/toggle/<key>', methods=['POST'])
def toggle_source(key):
    idx = int(request.form['idx'])
    channel_manager.toggle_source(key, idx)
    return redirect(url_for('edit_channel', key=key))

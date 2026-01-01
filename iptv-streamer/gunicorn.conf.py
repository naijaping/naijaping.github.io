# gunicorn.conf.py
bind = "0.0.0.0:8000"
workers = 4
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
accesslog = "/app/logs/access.log"
errorlog = "/app/logs/error.log"

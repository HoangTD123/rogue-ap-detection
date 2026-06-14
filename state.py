# state.py

import time
import threading
import queue
from collections import defaultdict

known_fingerprints = {}
seen               = defaultdict(dict)
alert_log          = []
prevention_log     = []

# Điều phối luồng (Thread Control)
stop_event     = threading.Event()
lock           = threading.Lock()
deauth_queue   = queue.Queue()

# Thời gian
last_save_time = time.time()
from threading import Timer
import datetime
import threading
import time
import re


class ip_entry():
    pool = None
    ip_addr = None

    def __init__(self, ip_addr, pool, logger,if_show,shining_pool):
        self.logger = logger
        self.ip_addr = ip_addr
        self.timer = 0
        self.timer = datetime.datetime.now()
        self.pool = pool
        self.fee = 3.0

        pool[str(ip_addr)] = self
        
        self.fee_rate = 1.0

        if ip_addr in shining_pool:
            self.fee_rate = 1.1


        self.thread = threading.Thread(target=self.print_fee)
        self._stop_event = threading.Event()
        if if_show:
            self.start()

    def get_live_time(self):
        self.logger.warn(self.ip_addr + " living for " + datetime.datetime.now() - self.timer)
        return datetime.datetime.now() - self.timer

    def start(self):
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        self.thread.join()

    def delete(self):
        self.logger.warn("Now delete IP " + self.ip_addr)
        self.stop()
        del self.pool[self.ip_addr]
        del self

    def print_fee(self):
        while not self._stop_event.is_set():
            time.sleep(1)
            living_time = datetime.datetime.now() - self.timer
            if living_time < datetime.timedelta(0, 60):
                self.fee = self.fee_rate * (self.fee + 0.08)
            elif living_time < datetime.timedelta(10, 0):
                self.fee = self.fee_rate* (1.001 * self.fee + 0.04)
            else:
                self.fee = self.fee_rate * 50

            if living_time % datetime.timedelta(0, 10) < datetime.timedelta(0, 1):
                self.logger.warn("IP[" + str(self.ip_addr) + "] has been leased for [" + str(
                    living_time) + "], resulting in a fee of [" + str(round(self.fee, 4)) + "]")

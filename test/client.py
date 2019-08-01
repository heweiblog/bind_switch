import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.6.104', 16688))

with open('zone.txt','w') as f:
	while True:
		d = s.recv(1024)
		if d:
			print(d.decode('utf-8'))
			#f.write(d.decode('utf-8'))
		else:
			print('over')
			break

s.close()

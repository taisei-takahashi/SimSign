import subprocess, sys

args = sys.argv
script = 'test.py'

for i in range(100):
	cp = subprocess.run(['python', script, args[1], args[2]])
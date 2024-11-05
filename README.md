# ScanMe

Requirements:

make sure that packages arjun and mitm6 are updated:
pip install --update arjun
pip install --update mitm6

In order to run the script, make it executable:

chmod +x scanme.py

Usage:

sudo python3 scanme.py <targetIP>

or use sudo python3 scanme.py -h for help options

Functions:

IP decoys
timeout
fragmentation
randomized scan patterns
port scan
banner grabbing
multithreading
file output
argument parsing
color-coded output

Examples:

python3 scanme.py <targetIP> -p21,22,23,25...
python3 scanme.py "<multiple_targets>" (make sure they are comma separated) -p21,22,23,25... (scan single or multiple ports)

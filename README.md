# sniffer
[![codecov](https://codecov.io/gh/marcenavuc/sniffer/branch/main/graph/badge.svg?token=UQTKD2SQMB)](https://codecov.io/gh/marcenavuc/sniffer)
[![Build Status](https://travis-ci.com/marcenavuc/sniffer.svg?branch=main)](https://travis-ci.com/marcenavuc/sniffer)

Автор: Аверченко Марк (https://vk.com/markenus)

## Описание
Простой сниффер на python, который может выводить приходящие
пакеты, а также сохранять трафик в формате pcap

## Требования
* Python версии ровно 3.8
* Все библиотеки из файла requirements.txt

## Установка
1) Скачайте репозиторий
`git clone marcenavuc/sniffer`
2) Установите зависимости
`pip install -r requirements.txt`

## Установить как пакет
1) Установите setuptools, wheel
```bash
$ python3 -m pip install setuptools wheel
```
2) Соберите исходный код для установки
```bash
$ python3 setup.py sdist bdist_wheel
```
3) Соберите исходники и установите пакет
```bash
$ python3 setup.py build
$ python3 setup.py install
```

## Состав
* CLI **sniffer/cli.py**
* Сниффер **sniffer/sniff.py**
* Описание Поддерживаемых протоколов **sniffer/protocols**
* Тесты: **tests/**

## Использование
` sudo venv/bin/python -m sniffer --count 1 --mac A8:1E:84:8B:16:E2`

```
usage: -m [-h] [--nopcap] [--count COUNT] [--file FILE] [--noudp] [--notcp] [--macs MACS [MACS ...]] [--ips IPS [IPS ...]] [--validate]

optional arguments:
  -h, --help            show this help message and exit
  --nopcap, -np         don't save pcap file
  --count COUNT         how many packets should be collected
  --file FILE, -f FILE  set path to pcap file
  --noudp, -nu          exclude udp
  --notcp, -            exclude tcp
  --macs MACS [MACS ...], -m MACS [MACS ...]
                        include only this mac address
  --ips IPS [IPS ...], -i IPS [IPS ...]
                        include only this ip address
  --validate, -v        if it's set, sniffer will validate packets

```

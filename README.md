# sniffer
[![codecov](https://codecov.io/gh/marcenavuc/sniffer/branch/main/graph/badge.svg?token=UQTKD2SQMB)](https://codecov.io/gh/marcenavuc/sniffer)

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
`sudo venv/bin/python3.8 -m sniffer`

```
usage: -m [-h] [-p] [-v] [--count COUNT]

optional arguments:
  -h, --help     show this help message and exit
  -p             don't save pcap file
  -v             print packets?
  --count COUNT  how many packets should be collected
```
